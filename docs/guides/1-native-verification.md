---
title: Native W3C DC Implementation (KMP)
sidebar_position: 2
---

# Enable Native W3C Digital Credentials in Your Kotlin Multiplatform App

:::warning iOS Support Coming Soon
Native W3C DC implementation is currently **only supported on Android**. iOS support will be available soon.
:::

This native implementation works on Android and uses platform-specific requirements:

- **Android**: Uses package name + certificate fingerprint for app identification

## **Overview**

The native W3C DC implementation allows your Android app to interact with verifiers through direct API calls, supporting secure and privacy-preserving credential presentment
flows. To implement this using the Multipaz SDK, these steps are required:

* Implementing the core W3C DC request flow (shared code)
* Implementing the `getAppToAppOrigin()` function for Android
* Setting up cryptographic key management (shared code)
* Configuring reader trust management for verifiers (shared code)
* Integrating the flow into your UI

## **Implementation Steps**

### **1. Initialize Required Components**

Before you can run the W3C DC flow, you need to initialize several shared, long-lived components. These components handle storage, cryptographic operations, trust management, and zero-knowledge proof capabilities required for the W3C DC protocol.

#### **`StorageTable`**

A `StorageTable` provides persistent key/value storage for your app. It's used to store W3C DC reader/verifier key material and other cryptographic keys that need to persist across app sessions.

You can initialize a storage table from platform-specific storage:

```kotlin
val storage = Platform.nonBackedUpStorage
val storageTable = storage.getTable(
    StorageTableSpec(
        name = "YourAppKeys",
        supportPartitions = false,
        supportExpiration = false
    )
)
```

**What it's used for:**

- Storing reader certificates and private keys
- Persisting cryptographic material across app restarts
- Maintaining verifier identity between sessions

**Device Security Requirements:**

The W3C DC implementation requires device-level security to be configured to properly protect stored cryptographic material:

- **Android**: Device lock screen must be configured (pattern, PIN, password, or fingerprint)

The app should work correctly when any of these authentication methods are enabled on the device. Without a device lock screen, cryptographic operations may fail or be restricted by the operating system.

#### **`AsymmetricKey.X509Certified` (IACA Key)**

The Issuing Authority Certification Authority (IACA) key material is used to create an issuer trust anchor and generate Document Signing (DS) certificates. This enables your app to verify the authenticity of credentials.

To set up the IACA key:

1. Load your IACA certificate (from resources, file system, or network)
2. Generate a new Document Signing (DS) private key
3. Combine them into an `AsymmetricKey.X509CertifiedExplicit`
4. Generate a DS certificate using `MdocUtil.generateDsCertificate()`

```kotlin
// Load IACA certificate from resources
// Place the .pem file in your resources (e.g., src/commonMain/composeResources/files/)
val iacaCert = X509Cert.fromPem(Res.readBytes("files/iaca_certificate.pem").decodeToString())

// Define certificate validity period
val now = Instant.fromEpochSeconds(Clock.System.now().epochSeconds)
val validFrom = now
val validUntil = now + 365.days

// Generate Document Signing key
val dsKey = Crypto.createEcPrivateKey(EcCurve.P256)

// Create IACA key with certificate chain
val iacaKey = AsymmetricKey.X509CertifiedExplicit(
    certChain = X509CertChain(certificates = listOf(iacaCert)),
    privateKey = dsKey,
)

// Generate DS certificate
val dsCert = MdocUtil.generateDsCertificate(
    iacaKey = iacaKey,
    dsKey = dsKey.publicKey,
    subject = X500Name.fromName(name = "CN=Your DS Key"),
    serial = ASN1Integer.fromRandom(numBits = 128),
    validFrom = validFrom,
    validUntil = validUntil
)
```

**Why this matters for W3C DC:**

- Enables credential issuer verification
- Validates the authenticity of credentials received from verifiers
- Required for building trust chains in the verification process

**IACA Certificate Files:**

IACA (Issuing Authority Certification Authority) certificates establish the root of trust for credential issuers. They are X.509 certificates in PEM format that you use to verify the authenticity of credentials.

- **File format**: PEM (Privacy-Enhanced Mail) format (`.pem` extension), which is a base64-encoded X.509 certificate
- **Source**: Obtain from your credential program administrator, issuer, or certificate authority
- **Loading**: Load from your app's resources/assets or obtain from a trusted source
- **Usage**: Parse using `X509Cert.fromPem()` which expects a PEM-formatted string

Refer to the [sample IACA certificate file](https://github.com/openwallet-foundation/multipaz-samples/blob/main/MultipazGettingStartedSample/composeApp/src/commonMain/composeResources/files/iaca_certificate.pem) for an example.

```kotlin
// Example: Loading IACA certificate from resources
// Place the .pem file in: src/commonMain/composeResources/files/
val iacaCert = X509Cert.fromPem(Res.readBytes("files/iaca_certificate.pem").decodeToString())

// Alternative: If you have the certificate as a String already
val iacaCertString = """
    -----BEGIN CERTIFICATE-----
    MIIE...
    -----END CERTIFICATE-----
""".trimIndent()
val iacaCert = X509Cert.fromPem(iacaCertString)
```

### **2. Understand the Core W3C DC Request Flow**

The W3C Digital Credentials flow involves several cryptographic operations and network requests.
Here's the core implementation:

```kotlin
suspend fun requestCredentialFromVerifier(
    appReaderKey: AsymmetricKey.X509Compatible,
    request: DocumentCannedRequest,
    protocol: RequestProtocol,
    format: CredentialFormat,
    zkSystemRepository: ZkSystemRepository
): DigitalCredentialResponse {
    
    // Step 1: Generate cryptographic materials
    val nonce = ByteString(Random.Default.nextBytes(16))
    val responseEncryptionKey = Crypto.createEcPrivateKey(EcCurve.P256)
    
    // Step 2: Get platform-specific app origin
    val origin = getAppToAppOrigin()
    // Note: "web-origin" is the W3C DC specification format identifier, not a requirement for web browsers
    val clientId = "web-origin:$origin"
    
    // Step 3: Build list of requested claims
    val claims = mutableListOf<MdocRequestedClaim>()
    request.mdocRequest!!.namespacesToRequest.forEach { namespaceRequest ->
        namespaceRequest.dataElementsToRequest.forEach { (mdocDataElement, intentToRetain) ->
            claims.add(
                MdocRequestedClaim(
                    namespaceName = namespaceRequest.namespace,
                    dataElementName = mdocDataElement.attribute.identifier,
                    intentToRetain = intentToRetain
                )
            )
        }
    }
    
    // Step 4: Build the W3C DC request
    val dcRequestObject = VerificationUtil.generateDcRequestMdoc(
        exchangeProtocols = protocol.exchangeProtocolNames,
        docType = request.mdocRequest!!.docType,
        claims = claims,
        nonce = nonce,
        origin = origin,
        clientId = clientId,
        responseEncryptionKey = responseEncryptionKey.publicKey,
        readerAuthenticationKey = if (protocol.signRequest) {
            appReaderKey  // Sign request to prove verifier identity
        } else {
            null
        },
        zkSystemSpecs = if (request.mdocRequest!!.useZkp) {
            zkSystemRepository.getAllZkSystemSpecs()
        } else {
            emptyList()
        }
    )
    
    // Step 5: Send request via W3C DC API
    val dcResponseObject = DigitalCredentials.Default.request(dcRequestObject)
    
    // Step 6: Decrypt and parse response
    val dcResponse = VerificationUtil.decryptDcResponse(
        response = dcResponseObject,
        nonce = nonce,
        origin = origin,
        responseEncryptionKey = AsymmetricKey.anonymous(
            privateKey = responseEncryptionKey,
            algorithm = responseEncryptionKey.curve.defaultKeyAgreementAlgorithm
        )
    )
    
    return dcResponse
}
```

**What does this do?**

* **Step 1**: Generates a random nonce (prevents replay attacks) and creates an ephemeral encryption
  key for the response
* **Step 2**: Gets the platform-specific app identifier (Android: package + certificate fingerprint)
* **Step 3**: Extracts the specific data elements (claims) being requested from the credential
* **Step 4**: Builds the W3C DC request object with all necessary parameters
* **Step 5**: Sends the request to the verifier server via the W3C DC API
* **Step 6**: Decrypts the response using the ephemeral key and validates it

Refer to
the [W3CDCCredentialsRequestButton implementation](https://github.com/openwallet-foundation/multipaz-samples/blob/main/MultipazGettingStartedSample/composeApp/src/commonMain/kotlin/org/multipaz/getstarted/w3cdc/W3CDCCredentialsRequestButton.kt#L428-L536)
for the complete reference implementation.

### **3. Set Up Reader Certificates**

Before making requests, you need to initialize reader certificates that authenticate your app as a
verifier:

```kotlin
suspend fun initializeReaderKeys(
    keyStorage: StorageTable
): AsymmetricKey.X509Certified {
    val certsValidFrom = LocalDate.parse("2024-12-01").atStartOfDayIn(TimeZone.UTC)
    val certsValidUntil = LocalDate.parse("2034-12-01").atStartOfDayIn(TimeZone.UTC)

    // Initialize reader root certificate (CA)
    val readerRootKey = initReaderRootCertificate(
        keyStorage = keyStorage,
        certsValidFrom = certsValidFrom,
        certsValidUntil = certsValidUntil
    )

    // Initialize reader certificate (operational key)
    val readerKey = initReaderCertificate(
        keyStorage = keyStorage,
        readerRootKey = readerRootKey,
        certsValidFrom = certsValidFrom,
        certsValidUntil = certsValidUntil
    )

    return readerKey
}

private suspend fun initReaderCertificate(
    keyStorage: StorageTable,
    readerRootKey: AsymmetricKey.X509CertifiedExplicit,
    certsValidFrom: Instant,
    certsValidUntil: Instant
): AsymmetricKey.X509Certified {
    // Try to retrieve existing key, or generate new one
    val readerPrivateKey = keyStorage.get("readerKey")
        ?.let { EcPrivateKey.fromDataItem(Cbor.decode(it.toByteArray())) }
        ?: run {
            val key = Crypto.createEcPrivateKey(EcCurve.P256)
            keyStorage.insert("readerKey", ByteString(Cbor.encode(key.toDataItem())))
            key
        }

    // Try to retrieve existing certificate, or generate new one
    val readerCert = keyStorage.get("readerCert")?.let {
        X509Cert.fromDataItem(Cbor.decode(it.toByteArray()))
    } ?: run {
        val cert = MdocUtil.generateReaderCertificate(
            readerRootKey = readerRootKey,
            readerKey = readerPrivateKey.publicKey,
            subject = X500Name.fromName("CN=My App Verifier"),
            serial = ASN1Integer.fromRandom(numBits = 128),
            validFrom = certsValidFrom,
            validUntil = certsValidUntil,
        )
        keyStorage.insert("readerCert", ByteString(Cbor.encode(cert.toDataItem())))
        cert
    }

    return AsymmetricKey.X509CertifiedExplicit(
        certChain = X509CertChain(listOf(readerCert) + readerRootKey.certChain.certificates),
        privateKey = readerPrivateKey
    )
}

private suspend fun initReaderRootCertificate(
    keyStorage: StorageTable,
    certsValidFrom: Instant,
    certsValidUntil: Instant
): AsymmetricKey.X509CertifiedExplicit {
    // Similar implementation for root certificate
    // See full example in W3CDCCredentialsRequestButton.kt
    // ...
}
```

**What does this do?**

* Creates or retrieves reader certificates from persistent storage
* Reader root certificate acts as a self-signed CA
* Reader certificate is signed by the root and used for actual requests
* Certificates are cached to avoid regenerating on every request

**Key Concepts:**

* **Reader Root Certificate**: The "root of trust" for your verifier app (like a CA)
* **Reader Certificate**: The operational certificate used to sign credential requests
* **Certificate Chain**: Links your reader cert back to the root cert for validation
* **Persistent Storage**: Keys are stored so they persist across app sessions

Refer to
the [reader initialization code](https://github.com/openwallet-foundation/multipaz-samples/blob/main/MultipazGettingStartedSample/composeApp/src/commonMain/kotlin/org/multipaz/getstarted/w3cdc/W3CDCCredentialsRequestButton.kt#L311-L426)
for complete implementation.

### **4. Implement getAppToAppOrigin() for Android**

The `getAppToAppOrigin()` function provides a unique identifier for your app on Android.

:::note iOS Support Coming Soon
iOS support for `getAppToAppOrigin()` is not yet available but will be coming soon. This implementation is currently Android-only.
:::

On Android, the app origin combines the package name with the SHA-256 fingerprint of the app's
signing certificate:

```kotlin
// composeApp/src/androidMain/kotlin/org/multipaz/getstarted/GetAppOrigin.kt
@Suppress("DEPRECATION")
fun getAppToAppOrigin(): String {
    val packageInfo = applicationContext.packageManager
        .getPackageInfo(applicationContext.packageName, PackageManager.GET_SIGNATURES)
    return getAppOrigin(packageInfo.signatures!![0].toByteArray())
}
```

**How it works:**

- Retrieves the app's signing certificate from the package manager
- Extracts the certificate's SHA-256 fingerprint
- Uses the Multipaz `getAppOrigin()` utility to format it properly
- Results in a unique identifier based on both package name and certificate

**Why certificate fingerprint?**

- Prevents package name spoofing (multiple apps can't share the same package + cert combination)
- Standard security practice on Android
- Ties the app identity to the developer's signing key

**What does this do?**

* Provides a unique origin identifier required by the W3C Digital Credentials specification
* Used in the `clientId` field of credential requests
* Helps verifiers identify which app is requesting credentials

**Reference Links:**

- [Android GetAppOrigin.kt](https://github.com/openwallet-foundation/multipaz-samples/blob/main/MultipazGettingStartedSample/composeApp/src/androidMain/kotlin/org/multipaz/getstarted/GetAppOrigin.kt)

### **5. Configure Android App Identifier**

:::note iOS Support Coming Soon
iOS configuration is not yet available. Native W3C DC is currently only supported on Android, with iOS support coming soon.
:::

#### **Android: AndroidManifest.xml**

Your Android app's package name is defined in the manifest:

```xml
<!-- composeApp/src/androidMain/AndroidManifest.xml -->
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="org.multipaz.getstarted">
    
    <application
        android:name=".MultipazGettingStartedApplication"
        android:label="Multipaz Getting Started">
        <!-- ... -->
    </application>
</manifest>
```

The certificate fingerprint comes from your signing key (configured in Gradle or generated during
build).

**What does this do?**

* Defines the Android app identifier
* Used by `getAppToAppOrigin()` to identify your app to verifiers
* Required for Android app distribution

### **6. Update Reader Trust Manager**

Configure your app to trust specific verifier applications and their reader certificates. This is **shared code** that works on both platforms:

```kotlin
// Initialize trust manager
val readerTrustManager = TrustManagerLocal(
    storage = storage, 
    identifier = "reader"
)

// Add trust for verifier applications
try {
    readerTrustManager.addX509Cert(
        certificate = X509Cert.fromPem(
            readerRootCertBytes.decodeToString()
        ),
        metadata = TrustMetadata(
            displayName = "Trusted Verifier Name",
            privacyPolicyUrl = "https://verifier.example.com"
        )
    )
} catch (e: TrustPointAlreadyExistsException) {
    // Certificate already exists, ignore
    e.printStackTrace()
}
```

**What does this do?**

* Establishes trust for specific verifier applications
* Ensures your app only responds to trusted verifiers
* Prevents unauthorized applications from accessing credential data
* **Works on Android** (iOS support coming soon)

**Required Certificate Files:**

Download these certificate files and add them to `/src/commonMain/composeResources/files`:

* [reader_root_cert_multipaz_testapp.pem](https://github.com/openwallet-foundation/multipaz-samples/blob/main/MultipazGettingStartedSample/composeApp/src/commonMain/composeResources/files/reader_root_cert_multipaz_testapp.pem)
* [reader_root_cert_multipaz_web_verifier.pem](https://github.com/openwallet-foundation/multipaz-samples/blob/main/MultipazGettingStartedSample/composeApp/src/commonMain/composeResources/files/reader_root_cert_multipaz_web_verifier.pem)

Refer
to [the trust manager initialization code](https://github.com/openwallet-foundation/multipaz-samples/blob/main/MultipazGettingStartedSample/composeApp/src/commonMain/kotlin/org/multipaz/getstarted/App.kt#L162-L249)
for complete implementation.

### **7. Integrate Into Your UI**

Now that you understand the core implementation, you can integrate it into your app's UI. Here's how
to call the credential request flow:

```kotlin
@Composable
fun MyCredentialSharingScreen(app: App) {
    val coroutineScope = rememberCoroutineScope()
    
    Button(onClick = {
        coroutineScope.launch {
            try {
                // Initialize reader keys
                val readerKey = initializeReaderKeys(app.storageTable)
                
                // Define what credential data to request
                val request = DrivingLicense.getDocumentType().cannedRequests.first()
                
                // Make the W3C DC request
                val response = requestCredentialFromVerifier(
                    appReaderKey = readerKey,
                    request = request,
                    protocol = RequestProtocol.W3C_DC_OPENID4VP_29,
                    format = CredentialFormat.ISO_MDOC,
                    zkSystemRepository = app.zkSystemRepository
                )
                
                // Handle the response
                when (response) {
                    is MdocApiDcResponse -> {
                        // Process mDoc format response
                        processDeviceResponse(response.deviceResponse)
                    }
                    is OpenID4VPDcResponse -> {
                        // Process OpenID4VP format response
                        processVpToken(response.vpToken)
                    }
                }
            } catch (e: Exception) {
                Logger.e("W3CDC", "Error requesting credentials", e)
                // Show error to user
            }
        }
    }) {
        Text("Share Credential with Verifier")
    }
}
```

**What does this do?**

* Creates a button that triggers the W3C DC flow
* Initializes reader keys on demand
* Specifies which credential type and data elements to request
* Handles both mDoc and OpenID4VP response formats
* Provides error handling for network/crypto failures

**For Testing/Demo:**

The sample app includes a pre-built `W3CDCCredentialsRequestButton` that implements all of this for
you:

```kotlin
// For testing/demo purposes only
W3CDCCredentialsRequestButton(
    promptModel = App.promptModel,
    storageTable = app.storageTable,
    zkSystemRepository = app.zkSystemRepository,
    showResponse = { vpToken, deviceResponse, sessionTranscript, nonce, eReaderKey, metadata ->
        // Handle response
    }
)
```

This button is useful for testing but in production you should implement the flow yourself as shown
above to have full control over the UX and error handling.

#### **Demo Screenshots**

<div style={{display: 'flex', flexDirection: 'row', justifyContent: 'space-between', alignItems: 'flex-start', gap: '12px'}}>
  <div style={{width: '22%', minWidth: 120, textAlign: 'center'}}>
    <img src="/img/dc_native_1.png" alt="Step 1: Credential Request in Browser" style={{width: '100%', borderRadius: 6}} />
    <div style={{fontSize: '0.9em', marginTop: 4}}>Step 1</div>
  </div>
  <div style={{width: '22%', minWidth: 120, textAlign: 'center'}}>
    <img src="/img/dc_native_2.png" alt="Step 2: Credential Selection in App" style={{width: '100%', borderRadius: 6}} />
    <div style={{fontSize: '0.9em', marginTop: 4}}>Step 2</div>
  </div>
  <div style={{width: '22%', minWidth: 120, textAlign: 'center'}}>
    <img src="/img/dc_native_3.png" alt="Step 3: Credential Sent to Verifier" style={{width: '100%', borderRadius: 6}} />
    <div style={{fontSize: '0.9em', marginTop: 4}}>Step 3</div>
  </div>
</div>


Refer
to [HomeScreen.kt](https://github.com/openwallet-foundation/multipaz-samples/blob/main/MultipazGettingStartedSample/composeApp/src/commonMain/kotlin/org/multipaz/getstarted/HomeScreen.kt#L186-L208)
to see the demo button usage.
