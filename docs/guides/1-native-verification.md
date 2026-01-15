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

Refer to the **[storage initialization code](https://github.com/openwallet-foundation/multipaz-samples/blob/ce8bec6f26159febd3ffa174b767184d5d9b3006/MultipazGettingStartedSample/composeApp/src/commonMain/kotlin/org/multipaz/getstarted/App.kt#L121C10-L128C14)** for the complete example.

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

Refer to the **[IACA certificate initialization code](https://github.com/openwallet-foundation/multipaz-samples/blob/ce8bec6f26159febd3ffa174b767184d5d9b3006/MultipazGettingStartedSample/composeApp/src/commonMain/kotlin/org/multipaz/getstarted/App.kt#L142-L168)** for more context.

**Why this matters for W3C DC:**

- Enables credential issuer verification
- Validates the authenticity of credentials received from verifiers
- Required for building trust chains in the verification process

**IACA Certificate Files:**

IACA (Issuing Authority Certification Authority) certificates establish the root of trust for credential issuers. They are X.509 certificates in PEM format that you use to verify the authenticity of credentials.

- **File format**: PEM (Privacy-Enhanced Mail) format (`.pem` extension), which is a base64-encoded X.509 certificate
- **Source**: Copy the sample certificate from the repository, or generate it using [multipazctl](https://github.com/openwallet-foundation/multipaz?tab=readme-ov-file#command-line-tool)
- **Loading**: Load from your app's resources/assets or obtain from a trusted source
- **Usage**: Parse using `X509Cert.fromPem()` which expects a PEM-formatted string

Refer to the **[sample IACA certificate file](https://github.com/openwallet-foundation/multipaz-samples/blob/main/MultipazGettingStartedSample/composeApp/src/commonMain/composeResources/files/iaca_certificate.pem)** for an example.

```kotlin
// Example: Loading IACA certificate from resources
// Place the .pem file in: src/commonMain/composeResources/files/
val iacaCert = X509Cert.fromPem(Res.readBytes("files/iaca_certificate.pem").decodeToString())

// Alternative: If you have the certificate as a String already
// val iacaCertString = """
//     -----BEGIN CERTIFICATE-----
//     MIIE...
//     -----END CERTIFICATE-----
// """.trimIndent()
// val iacaCert = X509Cert.fromPem(iacaCertString)
```

### **2. Understand the Core W3C DC Request Flow**

The W3C Digital Credentials flow involves several cryptographic operations and network requests.
Here's the concrete implementation from this sample project:

```kotlin
@OptIn(ExperimentalTime::class)
private suspend fun doDcRequestFlow(
    appReaderKey: AsymmetricKey.X509Compatible,
    request: DocumentCannedRequest,
    showResponse: (
        vpToken: JsonObject?,
        deviceResponse: DataItem?,
        sessionTranscript: DataItem,
        nonce: ByteString?,
        eReaderKey: EcPrivateKey?,
        metadata: ShowResponseMetadata
    ) -> Unit
) {
    require(request.mdocRequest != null) { "No ISO mdoc format in request" }

    // Step 1: Generate cryptographic materials
    // Random nonce for request/response correlation (prevents replay attacks)
    val nonce = ByteString(Random.Default.nextBytes(NONCE_SIZE_BYTES))
    
    // Ephemeral key for encrypting the response (ensures confidentiality)
    val responseEncryptionKey = Crypto.createEcPrivateKey(RESPONSE_ENCRYPTION_CURVE)

    // Step 2: Get platform-specific app origin
    val origin = getAppToAppOrigin()
    // Note: "web-origin" is the W3C DC specification format identifier
    val clientId = "web-origin:$origin"

    // Step 3: Configure protocol
    val protocolDisplayName = "OpenID4VP 1.0"
    val exchangeProtocolNames = listOf("openid4vp-v1-signed")

    // Step 4: Build list of requested claims
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

    // Step 5: Build the W3C DC request object
    val dcRequestObject = VerificationUtil.generateDcRequestMdoc(
        exchangeProtocols = exchangeProtocolNames,
        docType = request.mdocRequest!!.docType,
        claims = claims,
        nonce = nonce,
        origin = origin,
        clientId = clientId,
        responseEncryptionKey = responseEncryptionKey.publicKey,
        readerAuthenticationKey = appReaderKey,  // Sign request to prove verifier identity
        zkSystemSpecs = emptyList()
    )

    // Step 6: Send request via W3C DC API and measure response time
    val t0 = Clock.System.now()
    val dcResponseObject = DigitalCredentials.Default.request(dcRequestObject)

    // Step 7: Decrypt and parse response
    val dcResponse = VerificationUtil.decryptDcResponse(
        response = dcResponseObject,
        nonce = nonce,
        origin = origin,
        responseEncryptionKey = AsymmetricKey.anonymous(
            privateKey = responseEncryptionKey,
            algorithm = responseEncryptionKey.curve.defaultKeyAgreementAlgorithm
        )
    )

    // Step 8: Create metadata for analytics/logging
    val metadata = ShowResponseMetadata(
        engagementType = METADATA_ENGAGEMENT_TYPE,
        transferProtocol = "$METADATA_TRANSFER_PROTOCOL_PREFIX ($protocolDisplayName)",
        requestSize = Json.encodeToString(dcRequestObject).length.toLong(),
        responseSize = Json.encodeToString(dcResponseObject).length.toLong(),
        durationMsecNfcTapToEngagement = null,
        durationMsecEngagementReceivedToRequestSent = null,
        durationMsecRequestSentToResponseReceived = (Clock.System.now() - t0).inWholeMilliseconds
    )

    // Step 9: Handle response based on protocol format
    when (dcResponse) {
        is MdocApiDcResponse -> {
            // ISO 18013-7 mDoc format response
            showResponse(
                null, 
                dcResponse.deviceResponse, 
                dcResponse.sessionTranscript, 
                nonce, 
                null, 
                metadata
            )
        }

        is OpenID4VPDcResponse -> {
            // OpenID4VP format response
            showResponse(
                dcResponse.vpToken, 
                null, 
                dcResponse.sessionTranscript, 
                nonce, 
                null, 
                metadata
            )
        }
    }
}
```

**What does this do?**

* **Step 1**: Generates a random nonce (prevents replay attacks) and creates an ephemeral encryption key for the response
* **Step 2**: Gets the platform-specific app identifier (Android: package + certificate fingerprint)
* **Step 3**: Configures the exchange protocol (OpenID4VP in this example)
* **Step 4**: Extracts the specific data elements (claims) being requested from the credential
* **Step 5**: Builds the W3C DC request object with all necessary parameters including reader authentication
* **Step 6**: Sends the request via W3C DC API and measures response time
* **Step 7**: Decrypts the response using the ephemeral key and validates it
* **Step 8**: Creates metadata for tracking request/response sizes and timing
* **Step 9**: Handles the response based on format (mDoc API or OpenID4VP)

**Key Configuration Constants** (defined at the top of `W3CDCCredentialsRequestButton.kt`):

```kotlin
private const val NONCE_SIZE_BYTES = 16
private val RESPONSE_ENCRYPTION_CURVE = EcCurve.P256
private const val METADATA_ENGAGEMENT_TYPE = "OS-provided CredentialManager API"
private const val METADATA_TRANSFER_PROTOCOL_PREFIX = "W3C Digital Credentials"
```

See the **[complete implementation](https://github.com/openwallet-foundation/multipaz-samples/blob/ce8bec6f26159febd3ffa174b767184d5d9b3006/MultipazGettingStartedSample/composeApp/src/commonMain/kotlin/org/multipaz/getstarted/w3cdc/W3CDCCredentialsRequestButton.kt#L427-L551)** for full context.

### **3. Set Up Reader Certificates**

Before making requests, you need to initialize reader certificates that authenticate your app as a verifier. Here's the concrete implementation from this sample project:

#### **Main Initialization Flow**

```kotlin
Button(onClick = {
    coroutineScope.launch {
        // Parse certificate validity dates from constants
        val certsValidFrom = LocalDate.parse(CERT_VALID_FROM_DATE).atStartOfDayIn(TimeZone.UTC)
        val certsValidUntil = LocalDate.parse(CERT_VALID_UNTIL_DATE).atStartOfDayIn(TimeZone.UTC)

        // Step 1: Initialize the reader root key and certificate
        // This is the "root of trust" for your verifier application
        val readerRootKey = readerRootInit(
            keyStorage = storageTable,
            certsValidFrom = certsValidFrom,
            certsValidUntil = certsValidUntil
        )

        // Step 2: Initialize the reader key and certificate
        // This is the operational key used to sign credential requests
        val readerKey = readerInit(
            keyStorage = storageTable,
            readerRootKey = readerRootKey,
            certsValidFrom = certsValidFrom,
            certsValidUntil = certsValidUntil
        )

        // Step 3: Execute the credential request flow
        doDcRequestFlow(
            appReaderKey = readerKey,
            request = requestOptions.first().sampleRequest,
            showResponse = showResponse
        )
    }
}) {
    Text(text = text)
}
```

See the **[complete implementation](https://github.com/openwallet-foundation/multipaz-samples/blob/ce8bec6f26159febd3ffa174b767184d5d9b3006/MultipazGettingStartedSample/composeApp/src/commonMain/kotlin/org/multipaz/getstarted/w3cdc/W3CDCCredentialsRequestButton.kt#L129-L197)** for full context.
#### **Reader Certificate Initialization**

```kotlin
@OptIn(ExperimentalTime::class)
private suspend fun readerInit(
    keyStorage: StorageTable,
    readerRootKey: AsymmetricKey.X509CertifiedExplicit,
    certsValidFrom: Instant,
    certsValidUntil: Instant
): AsymmetricKey.X509Certified {
    // Try to retrieve existing reader private key from storage
    // If not found, generate a new one
    val readerPrivateKey = keyStorage.get(STORAGE_KEY_READER_PRIVATE_KEY)
        ?.let { EcPrivateKey.fromDataItem(Cbor.decode(it.toByteArray())) }
        ?: run {
            // Generate new P-256 private key
            val key = Crypto.createEcPrivateKey(READER_KEY_CURVE)
            // Persist to storage using CBOR encoding
            keyStorage.insert(
                STORAGE_KEY_READER_PRIVATE_KEY,
                ByteString(Cbor.encode(key.toDataItem()))
            )
            key
        }

    // Try to retrieve existing reader certificate from storage
    // If not found, generate a new one signed by the root key
    val readerCert = keyStorage.get(STORAGE_KEY_READER_CERT)?.let {
        X509Cert.fromDataItem(Cbor.decode(it.toByteArray()))
    }
        ?: run {
            // Generate reader certificate signed by reader root
            val cert = MdocUtil.generateReaderCertificate(
                readerRootKey = readerRootKey,
                readerKey = readerPrivateKey.publicKey,
                subject = X500Name.fromName(CERT_SUBJECT_COMMON_NAME),
                serial = ASN1Integer.fromRandom(numBits = CERT_SERIAL_NUMBER_BITS),
                validFrom = certsValidFrom,
                validUntil = certsValidUntil,
            )
            // Persist certificate to storage
            keyStorage.insert(
                STORAGE_KEY_READER_CERT,
                ByteString(Cbor.encode(cert.toDataItem()))
            )
            cert
        }

    // Return the complete certificate chain: [Reader Cert, Reader Root Cert]
    return AsymmetricKey.X509CertifiedExplicit(
        certChain = X509CertChain(listOf(readerCert) + readerRootKey.certChain.certificates),
        privateKey = readerPrivateKey
    )
}
```

See the **[complete implementation](https://github.com/openwallet-foundation/multipaz-samples/blob/ce8bec6f26159febd3ffa174b767184d5d9b3006/MultipazGettingStartedSample/composeApp/src/commonMain/kotlin/org/multipaz/getstarted/w3cdc/W3CDCCredentialsRequestButton.kt#L226-L275)** for full context.

#### **Reader Root Certificate Initialization**

```kotlin
// From: W3CDCCredentialsRequestButton.kt
@OptIn(ExperimentalTime::class, ExperimentalResourceApi::class)
private suspend fun readerRootInit(
    keyStorage: StorageTable,
    certsValidFrom: Instant,
    certsValidUntil: Instant
): AsymmetricKey.X509CertifiedExplicit {
    // Load the bundled P-384 reader root key from resources
    val readerRootKey = loadBundledReaderRootKey()

    // Try to retrieve existing root private key
    // If not found, use the bundled key
    val readerRootPrivateKey = keyStorage.get(STORAGE_KEY_READER_ROOT_PRIVATE_KEY)
        ?.let { EcPrivateKey.fromDataItem(Cbor.decode(it.toByteArray())) }
        ?: run {
            // Store bundled key for future use
            keyStorage.insert(
                STORAGE_KEY_READER_ROOT_PRIVATE_KEY,
                ByteString(Cbor.encode(readerRootKey.toDataItem()))
            )
            readerRootKey
        }

    // Try to retrieve existing root certificate
    // If not found, generate self-signed root certificate
    val readerRootCert = keyStorage.get(STORAGE_KEY_READER_ROOT_CERT)
        ?.let { X509Cert.fromDataItem(Cbor.decode(it.toByteArray())) }
        ?: run {
            // Generate self-signed root certificate
            val bundledReaderRootCert = MdocUtil.generateReaderRootCertificate(
                readerRootKey = AsymmetricKey.anonymous(readerRootKey),
                subject = X500Name.fromName(CERT_SUBJECT_COMMON_NAME),
                serial = ASN1Integer.fromRandom(numBits = CERT_SERIAL_NUMBER_BITS),
                validFrom = certsValidFrom,
                validUntil = certsValidUntil,
                crlUrl = CERT_CRL_URL
            )
            // Persist root certificate
            keyStorage.insert(
                STORAGE_KEY_READER_ROOT_CERT,
                ByteString(Cbor.encode(bundledReaderRootCert.toDataItem()))
            )
            bundledReaderRootCert
        }

    println("readerRootCert: ${readerRootCert.toPem()}")

    return AsymmetricKey.X509CertifiedExplicit(
        certChain = X509CertChain(listOf(readerRootCert)),
        privateKey = readerRootPrivateKey
    )
}
```

See the **[complete implementation](https://github.com/openwallet-foundation/multipaz-samples/blob/ce8bec6f26159febd3ffa174b767184d5d9b3006/MultipazGettingStartedSample/composeApp/src/commonMain/kotlin/org/multipaz/getstarted/w3cdc/W3CDCCredentialsRequestButton.kt#L303-L351)** for full context.

**Key Configuration Constants** (from `W3CDCCredentialsRequestButton.kt`):

```kotlin
// Storage key names for persisting cryptographic materials
private const val STORAGE_KEY_READER_ROOT_PRIVATE_KEY = "readerRootKey"
private const val STORAGE_KEY_READER_ROOT_CERT = "readerRootCert"
private const val STORAGE_KEY_READER_PRIVATE_KEY = "readerKey"
private const val STORAGE_KEY_READER_CERT = "readerCert"

// Certificate validity dates (10-year validity period)
private const val CERT_VALID_FROM_DATE = "2024-12-01"
private const val CERT_VALID_UNTIL_DATE = "2034-12-01"

// Certificate subject and CRL configuration
private const val CERT_SUBJECT_COMMON_NAME = "CN=OWF Multipaz Getting Started Reader Cert"
private const val CERT_CRL_URL = 
    "https://github.com/openwallet-foundation-labs/identity-credential/crl"

// Cryptographic parameters
private const val CERT_SERIAL_NUMBER_BITS = 128
private val READER_KEY_CURVE = EcCurve.P256       // Reader operational key
private val READER_ROOT_KEY_CURVE = EcCurve.P384  // Reader root key
```

**What does this do?**

* Creates or retrieves reader certificates from persistent storage
* Reader root certificate acts as a self-signed CA (Certificate Authority)
* Reader certificate is signed by the root and used for actual credential requests
* Certificates are cached to avoid regenerating on every request
* Uses P-256 for operational keys and P-384 for root keys

**Key Concepts:**

* **Reader Root Certificate**: The "root of trust" for your verifier app (like a CA)
* **Reader Certificate**: The operational certificate used to sign credential requests
* **Certificate Chain**: Links your reader cert back to the root cert for validation
* **Persistent Storage**: Keys are stored using CBOR encoding so they persist across app sessions
* **Bundled Keys**: This sample uses pre-generated keys from resources for demonstration

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

- [Android Platform.kt](https://github.com/openwallet-foundation/multipaz-samples/blob/ce8bec6f26159febd3ffa174b767184d5d9b3006/MultipazGettingStartedSample/composeApp/src/androidMain/kotlin/org/multipaz/getstarted/Platform.kt)

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

* **[reader_root_cert_multipaz_testapp.pem](https://github.com/openwallet-foundation/multipaz-samples/blob/main/MultipazGettingStartedSample/composeApp/src/commonMain/composeResources/files/reader_root_cert_multipaz_testapp.pem)**
* **[reader_root_cert_multipaz_web_verifier.pem](https://github.com/openwallet-foundation/multipaz-samples/blob/main/MultipazGettingStartedSample/composeApp/src/commonMain/composeResources/files/reader_root_cert_multipaz_web_verifier.pem)**

Refer to **[the trust manager initialization code](https://github.com/openwallet-foundation/multipaz-samples/blob/ce8bec6f26159febd3ffa174b767184d5d9b3006/MultipazGettingStartedSample/composeApp/src/commonMain/kotlin/org/multipaz/getstarted/App.kt#L205-L220)**
for complete implementation.

### **7. Integrate Into Your UI**

Now that you understand the core implementation, you can integrate it into your app's UI. The sample app provides a reusable `W3CDCCredentialsRequestButton` component that you can use in your screens.

#### **Using W3CDCCredentialsRequestButton**

Here's how to integrate the W3C Digital Credentials button in your UI (example from `HomeScreen.kt`):

```kotlin
@Composable
fun HomeScreen(
    app: App,
    navController: NavController,
    documents: List<Document>,
    // ... other parameters
) {
    Column(
        modifier = Modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        // ... your other UI components

        // Only show the button when documents are available and on Android
        AnimatedVisibility(documents.isNotEmpty()) {
            if (isAndroid()) {
                W3CDCCredentialsRequestButton(
                    promptModel = App.promptModel,
                    storageTable = app.storageTable,
                    text = "W3CDC Credentials Request",  // Optional: customize button text
                    showResponse = { vpToken, deviceResponse, sessionTranscript, nonce, eReaderKey, metadata ->
                        // Encode response data as base64url for navigation
                        val vpTokenString = vpToken
                            ?.let { Json.encodeToString(it) }
                            ?.encodeToByteArray()
                            ?.toBase64Url() ?: "_"

                        val deviceResponseString = deviceResponse
                            ?.let { Cbor.encode(it).toBase64Url() }
                            ?: "_"

                        val sessionTranscriptString = Cbor.encode(sessionTranscript).toBase64Url()

                        val nonceString = nonce
                            ?.let { nonce.toByteArray().toBase64Url() }
                            ?: "_"

                        val eReaderKeyString = eReaderKey
                            ?.let { Cbor.encode(eReaderKey.toCoseKey().toDataItem()).toBase64Url() }
                            ?: "_"

                        val metadataString = Cbor.encode(metadata.toDataItem()).toBase64Url()
                        
                        // Navigate to a screen that displays the response
                        val route = "show_response/$vpTokenString/$deviceResponseString/$sessionTranscriptString/$nonceString/$eReaderKeyString/$metadataString"
                        navController.navigate(route)
                    }
                )
            }
        }
    }
}
```
Refer to **[HomeScreen.kt](https://github.com/openwallet-foundation/multipaz-samples/blob/a56a2ba9f915d7c65ac31f8fc4a17600c5fd1873/MultipazGettingStartedSample/composeApp/src/commonMain/kotlin/org/multipaz/getstarted/HomeScreen.kt#L202C2-L245C10)** file for context.
#### **Understanding the showResponse Callback**

The `showResponse` callback receives six parameters with credential data:

1. **`vpToken: JsonObject?`** - OpenID4VP format response (if using OpenID4VP protocol)
2. **`deviceResponse: DataItem?`** - ISO 18013-7 mDoc format response (if using mDoc API protocol)
3. **`sessionTranscript: DataItem`** - Cryptographic binding between request and response
4. **`nonce: ByteString?`** - The nonce used for request/response correlation
5. **`eReaderKey: EcPrivateKey?`** - The ephemeral reader key (for advanced scenarios)
6. **`metadata: ShowResponseMetadata`** - Performance and protocol metadata

**ShowResponseMetadata Structure:**

```kotlin
data class ShowResponseMetadata(
    val engagementType: String,              // e.g., "OS-provided CredentialManager API"
    val transferProtocol: String,            // e.g., "W3C Digital Credentials (OpenID4VP 1.0)"
    val requestSize: Long,                   // Size of request in bytes
    val responseSize: Long,                  // Size of response in bytes
    val durationMsecNfcTapToEngagement: Long?,          // N/A for W3C DC (null)
    val durationMsecEngagementReceivedToRequestSent: Long?,  // N/A for W3C DC (null)
    val durationMsecRequestSentToResponseReceived: Long     // Request-to-response latency
)
```
Refer to **[ShowResponseMetadata.kt](https://github.com/openwallet-foundation/multipaz-samples/blob/ce8bec6f26159febd3ffa174b767184d5d9b3006/MultipazGettingStartedSample/composeApp/src/commonMain/kotlin/org/multipaz/getstarted/w3cdc/ShowResponseMetadata.kt)** file for context.

#### **Processing and Displaying the Response**

After receiving the credential response, you need to display the data. Here's how this sample project handles it:

##### **Navigation Setup in App.kt**

```kotlin
// From: App.kt
composable<Destination.ShowResponseDestination> { backStackEntry ->
    val destination = backStackEntry.toRoute<Destination.ShowResponseDestination>()
    
    // Decode the vpToken from base64url-encoded JSON
    val vpToken = destination.vpResponse?.let {
        if (it != "_") Json.decodeFromString<JsonObject>(
            it.fromBase64Url().decodeToString()
        ) else null
    }
    
    // Decode the session transcript from base64url-encoded CBOR
    val sessionTranscript =
        Cbor.decode(destination.sessionTranscript.fromBase64Url())
    
    // Decode the nonce from base64url
    val nonce = destination.nonce?.let { ByteString(it.fromBase64Url()) }
    
    // Navigate to the response screen
    ShowResponseScreen(
        vpToken = vpToken,
        sessionTranscript = sessionTranscript,
        nonce = nonce,
        documentTypeRepository = documentTypeRepository,
        goBack = {
            navController.popBackStack()
        }
    )
}
```

See **[App.kt navigation setup](https://github.com/openwallet-foundation/multipaz-samples/blob/ce8bec6f26159febd3ffa174b767184d5d9b3006/MultipazGettingStartedSample/composeApp/src/commonMain/kotlin/org/multipaz/getstarted/App.kt#L406-L425)** for full context.

##### **Verifying and Parsing the Response**

The `ShowResponseScreen` verifies the cryptographic integrity of the response and extracts the credential data:

```kotlin
// From: ShowResponseDestination.kt
@Composable
fun ShowResponseScreen(
    vpToken: JsonObject?,
    sessionTranscript: DataItem?,
    nonce: ByteString?,
    documentTypeRepository: DocumentTypeRepository?,
    goBack: () -> Unit
) {
    val verificationResult =
        remember { mutableStateOf<VerificationResult>(VerificationResult.Loading) }
    val verificationResultValue = verificationResult.value

    // Verify and parse the response when screen loads
    LaunchedEffect(Unit) {
        val now = Clock.System.now()
        if (sessionTranscript == null) {
            verificationResult.value = VerificationResult.Error("Session transcript is null")
            return@LaunchedEffect
        }
        try {
            verificationResult.value = parseResponse(
                now = now,
                vpToken = vpToken,
                sessionTranscript = sessionTranscript,
                nonce = nonce,
                documentTypeRepository = documentTypeRepository,
            )
        } catch (e: Throwable) {
            Logger.e(TAG, "Error parsing response", e)
            verificationResult.value = VerificationResult.Error("Error parsing response")
        }
    }

    // Display loading, error, or success state
    when (verificationResultValue) {
        is VerificationResult.Error -> Box(
            contentAlignment = Alignment.Center,
        ) {
            Text(
                text = "Error: ${verificationResultValue.errorMessage}",
                style = MaterialTheme.typography.headlineMedium,
                color = MaterialTheme.colorScheme.error
            )
        }

        is VerificationResult.Loading -> Box(
            contentAlignment = Alignment.Center,
        ) {
            CircularProgressIndicator()
        }

        is VerificationResult.Success -> SuccessScreen(
            values = verificationResultValue.documentValues,
            goBack = goBack
        )
    }
}
```

##### **Response Verification Logic**

```kotlin
// From: ShowResponseDestination.kt
@OptIn(ExperimentalTime::class)
private suspend fun parseResponse(
    now: Instant,
    vpToken: JsonObject?,
    sessionTranscript: DataItem,
    nonce: ByteString?,
    documentTypeRepository: DocumentTypeRepository?
): VerificationResult {
    val documentValues: MutableList<DocumentValue> = mutableListOf()

    // Verify the OpenID4VP response
    val verifiedPresentations = if (vpToken != null) {
        verifyOpenID4VPResponse(
            now = now,
            vpToken = vpToken,
            sessionTranscript = sessionTranscript,
            nonce = nonce!!,
            documentTypeRepository = documentTypeRepository,
            zkSystemRepository = null
        )
    } else {
        throw IllegalStateException("vpToken must be non-null")
    }

    // Extract credential claims from verified presentations
    verifiedPresentations.forEachIndexed { vpNum, verifiedPresentation ->
        if (verifiedPresentation is MdocVerifiedPresentation) {
            verifiedPresentation.issuerSignedClaims.forEach { claim ->
                if (claim.attribute?.type == DocumentAttributeType.Picture) {
                    // Handle image data (e.g., portrait photo)
                    val image = decodeImage(claim.value.asBstr)
                    documentValues.add(
                        DocumentValue.ValueImage(image)
                    )
                } else {
                    // Handle text data (e.g., name, date of birth, license number)
                    documentValues.add(
                        DocumentValue.ValueText(
                            title = claim.attribute?.displayName ?: "Unknown",
                            value = claim.render()
                        )
                    )
                }
            }
        }
    }
    return VerificationResult.Success(documentValues)
}

private sealed class VerificationResult() {
    data object Loading : VerificationResult()
    data class Success(val documentValues: List<DocumentValue>) : VerificationResult()
    data class Error(val errorMessage: String) : VerificationResult()
}
```

See **[ShowResponseDestination.kt](https://github.com/openwallet-foundation/multipaz-samples/blob/ce8bec6f26159febd3ffa174b767184d5d9b3006/MultipazGettingStartedSample/composeApp/src/commonMain/kotlin/org/multipaz/getstarted/ShowResponseDestination.kt#L53-L287)** for the complete implementation.

**What this does:**

* **Step 1**: Decodes the response data from base64url encoding
* **Step 2**: Verifies the cryptographic signatures using `verifyOpenID4VPResponse()`
* **Step 3**: Validates the session transcript binding between request and response
* **Step 4**: Verifies the nonce matches to prevent replay attacks
* **Step 5**: Extracts and parses individual claims (data elements) from the credential
* **Step 6**: Separates image data (portraits) from text data (names, dates, etc.)
* **Step 7**: Displays the verified credential data in a user-friendly UI

**Key Security Features:**

* **Cryptographic Verification**: All signatures are verified before displaying data
* **Session Binding**: The session transcript ensures the response matches the request
* **Nonce Validation**: Prevents replay attacks by verifying the nonce
* **Type Safety**: Uses sealed classes to handle loading, success, and error states
* **Error Handling**: Gracefully handles verification failures

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
