# Deploying Multipaz Servers to Google Cloud Run

## **Before You Begin**

This tutorial guides you through deploying the Multipaz [OpenID4VCI Server](https://github.com/openwallet-foundation/multipaz/tree/main/multipaz-openid4vci-server) , [Records Server](https://github.com/openwallet-foundation/multipaz/tree/main/multipaz-records-server) and [Verifier Server](https://github.com/openwallet-foundation/multipaz/tree/main/multipaz-verifier-server) to Google Cloud Run. These servers work together to provide a complete credential issuance system where the OpenID4VCI server issues credentials based on identity data stored in the Records server. The deployment methods for the three servers are similar. Here, I’ll use the OpenID4VCI and Records servers as examples. The verifier server setup is similar to the OpenID4VCI flow.

---

## **Prerequisites**

* A Google Cloud Platform (GCP) account with billing enabled
* Google Cloud SDK (`gcloud`) installed and configured
* Docker installed (for local testing, though Cloud Build handles this)
* Basic understanding of containerization and cloud deployment
* Familiarity with the Multipaz project structure
* Access to the `multipaz` repository
* Source code pulled/cloned locally: Before running `buildFatJar`, you need to pull the source code from the `multipaz` repository and have it ready for building on your local machine
* Google Cloud project with Cloud Run API enabled
* Terminal/command line access
* Java 17+ (for building the JAR files)

---

## **What You'll Learn**

* How to configure servers for Cloud Run deployment
* How to build fat JAR files with all dependencies
* How to create Docker images for the servers
* How to deploy servers to Google Cloud Run
* How to connect the OpenID4VCI server to the Records server

---


## **Configuration Changes**

In [this commit](https://github.com/hanluOMH/identity-credential/commit/bd51ad7dc8fd128491da7dff709e7f36eda30330) from the [`deploy_cloud` branch](https://github.com/hanluOMH/identity-credential/tree/deploy_cloud), several configuration changes were made to prepare the servers for Cloud Run deployment:

### **Changes to `multipaz-openid4vci-server`**

The following changes were made to `multipaz-openid4vci-server/src/main/resources/resources/default_configuration.json`:

1. **Port Configuration**: Changed `server_port` from `8007` to `8080`
   - **Why use 8080?** Google Cloud Run defaults to port 8080 for all services. Using 8080 ensures your service works without additional configuration.
   - **If you need a different port:** If your service must use a different port (e.g., 9090), you can specify it when deploying:
     ```bash
     gcloud run deploy multipaz-openid4vci-server \
       --image gcr.io/YOUR-PROJECT-ID/multipaz-openid4vci-server \
       --port 9090
     ```
     Then update your `server_port` configuration to match (e.g., `9090`).
   - The PORT environment variable can override this if needed

2. **Base URL Configuration**: Added `base_url` pointing to the Cloud Run deployment URL
   ```json
   "base_url": "https://multipaz-openid4vci-server-971523157550.us-central1.run.app"
   ```
   
   :::warning ⚠️ Important
   Replace this with your own Cloud Run deployment URL after deploying the server
   :::
   
   - This ensures all redirects and generated URLs use the correct public URL
   - Without this, the server would generate URLs with `localhost:8080`

3. **System of Record URL**: Added `system_of_record_url` pointing to the Records server
   ```json
   "system_of_record_url": "https://multipaz-records-server-971523157550.us-central1.run.app"
   ```
   
   :::warning ⚠️ Important
   Replace this with your own Records server Cloud Run URL after deploying it
   :::
   
   - This connects the OpenID4VCI server to the Records server
   - The OpenID4VCI server uses this to retrieve identity data when issuing credentials

### **Changes to `multipaz-records-server`**

The following changes were made to `multipaz-records-server/src/main/resources/resources/default_configuration.json`:

1. **Port Configuration**: Changed `server_port` from `8004` to `8080`
   - **Why use 8080?** Google Cloud Run defaults to port 8080 for all services. Using 8080 ensures your service works without additional configuration.
   - **If you need a different port:** If your service must use a different port (e.g., 9090), you can specify it when deploying:
     ```bash
     gcloud run deploy multipaz-records-server \
       --image gcr.io/YOUR-PROJECT-ID/multipaz-records-server \
       --port 9090
     ```
     Then update your `server_port` configuration to match (e.g., `9090`).

2. **Base URL Configuration**: Added `base_url` pointing to the Cloud Run deployment URL
   ```json
   "base_url": "https://multipaz-records-server-971523157550.us-central1.run.app"
   ```
   
   :::warning ⚠️ Important
   Replace this with your own Cloud Run deployment URL after deploying the server
   :::
   
   - Ensures proper redirects when accessing the root URL

3. **Admin Password**: Added fixed `admin_password` set to `"multipaz-records"`
   - Previously, the server generated a random password on each startup
   - This makes the password predictable and manageable for deployment

---

## **Deployment Steps**

:::warning ⚠️ Important
Deploy the Records server first, then update the `system_of_record_url` in the OpenID4VCI server configuration before deploying it.
:::

:::tip 💡 Getting Started
Before running the deployment commands, you should activate Cloud Shell from the Google Cloud Run console. Click the "Activate Cloud Shell" button (or press `G` then `S` for keyboard shortcut) to open a terminal in your browser where you can run all the commands.
:::

### **Step 1: Create Dockerfile**

Create a Dockerfile for the Records server in the `multipaz-records-server` directory:

```bash
mkdir -p multipaz-records-server && cat > multipaz-records-server/Dockerfile <<'EOF'
FROM eclipse-temurin:17-jre
WORKDIR /app
COPY app.jar app.jar
# Cloud Run sets PORT environment variable; pass it to the server using -param format
CMD ["sh","-c","java -jar app.jar -param server_port=${PORT:-8080}"]
EOF
```

**Command Explanation:**
- `mkdir -p multipaz-records-server`: Creates a directory named `multipaz-records-server` (the `-p` flag creates parent directories if needed and doesn't error if the directory already exists)
- `cat > multipaz-records-server/Dockerfile <<'EOF'`: Creates a file called `Dockerfile` inside `multipaz-records-server` and writes everything until `EOF` into that file
  - The `<<'EOF'` syntax is a "here document" that allows multi-line input
  - The single quotes around `EOF` prevent variable expansion in the content

**Dockerfile Contents Explanation:**
- `FROM eclipse-temurin:17-jre`: Uses Java 17 JRE base image (matches the server's Java version requirement)
- `WORKDIR /app`: Sets the working directory inside the container
- `COPY app.jar app.jar`: Copies the fat JAR file into the container
- `CMD`: Runs the JAR with the PORT environment variable passed as a parameter
  - Note: Uses `-param server_port=` format (not `--server.port=`) because this is a Ktor server
  - `${PORT:-8080}` uses Cloud Run's PORT environment variable, defaulting to 8080 if not set

### **Step 2: Build the Fat JAR**

Build the fat JAR file that includes all dependencies:

```bash
./gradlew :multipaz-records-server:buildFatJar
```

**What this does:**
- Compiles the Kotlin code
- Packages all dependencies into a single JAR file
- Includes the configuration files (including `default_configuration.json`)
- Outputs the JAR to `multipaz-records-server/build/libs/multipaz-records-server-all.jar`

**Note:** The Ktor Gradle plugin creates a fat JAR named `multipaz-records-server-all.jar`. We need to rename it to `app.jar` because the Dockerfile expects `app.jar`.

### **Step 3: Prepare for Cloud Build**

Upload the JAR file to Cloud Shell:

1. In the Cloud Shell terminal, click on the three-dot "More" menu icon (⋮) in the top right
2. Select **Upload** from the menu
3. A file selection dialog will open. Navigate to and select your `app.jar` file 
4. The file will be uploaded to your home directory (e.g., `/home/YOUR-PROJECT-ID/multipaz-records-server`)
   - **Note:** `YOUR-PROJECT-ID` is a placeholder - replace it with your actual project name or username



**Directory structure should look like:**
```
multipaz-records-server/
├── Dockerfile
└── app.jar
```

### **Step 4: Create Environment Variables File**

Create an `env-vars.yaml` file in the `multipaz-records-server/` directory with the `system_of_record_jwk` variable:

```bash
cat > multipaz-records-server/env-vars.yaml <<'EOF'
system_of_record_jwk: ''
EOF
```

:::warning ⚠️ Important
**Use your own JWK** - Replace the empty string `''` above with your own JWK (JSON Web Key) used for authenticating with the Records server.
:::

### **Step 5: Build Docker Image**

Build the Docker image using Google Cloud Build:

```bash
gcloud builds submit multipaz-records-server --tag gcr.io/YOUR-PROJECT-ID/multipaz-records-server
```

**Explanation:**
- `gcloud builds submit`: Submits a build to Google Cloud Build
- `multipaz-records-server`: The directory containing the Dockerfile and JAR file
- `--tag`: Tags the resulting image with the specified name
- `gcr.io/YOUR-PROJECT-ID/`: Your GCP project's Container Registry path
  - Replace `YOUR-PROJECT-ID` with your actual GCP project ID

**What happens:**
1. Cloud Build reads the Dockerfile
2. Builds a Docker image containing the JAR file
3. Pushes the image to Google Container Registry
4. The image is ready to be deployed to Cloud Run

### **Step 6: Deploy to Cloud Run**

Deploy the containerized application to Cloud Run:

```bash
gcloud run deploy multipaz-records-server \
  --image gcr.io/YOUR-PROJECT-ID/multipaz-records-server \
  --platform managed \
  --region us-central1 \
  --env-vars-file multipaz-records-server/env-vars.yaml \
  --allow-unauthenticated
```

**Parameters explained:**
- `--image`: Specifies the Docker image to deploy (from Step 5)
- `--platform managed`: Uses Google's fully managed Cloud Run platform
- `--region us-central1`: Deploys to the specified region
  - Choose a region close to your users for better performance
- `--port`: (Optional) Specifies the port your service listens on
  - Defaults to 8080 if not specified (Cloud Run's default)
  - Only needed if your service uses a different port (e.g., `--port 9090`)
  - Must match the `server_port` in your configuration file
- `--env-vars-file`: Specifies the environment variables file created in Step 4
- `--allow-unauthenticated`: Makes the service publicly accessible
  - Remove this flag if you want to require authentication

**After deployment:**
- Cloud Run will provide a URL like: `https://multipaz-records-server-XXXXX.us-central1.run.app`
- **Save this URL** - you'll need it to update the `system_of_record_url` in the OpenID4VCI server configuration
- Update the `base_url` in your Records server configuration file with this URL if needed

---

## **Deploying the OpenID4VCI Server**

After deploying the Records server, update the `system_of_record_url` in the OpenID4VCI server configuration with the Records server URL you obtained above, then follow these steps:

### **Step 1: Update Configuration**

Before building, update `multipaz-openid4vci-server/src/main/resources/resources/default_configuration.json`:

1. Update `system_of_record_url` with your Records server URL:
   ```json
   "system_of_record_url": "https://YOUR-RECORDS-SERVER-URL"
   ```
   
   :::warning ⚠️ Important
   Replace `YOUR-RECORDS-SERVER-URL` with the actual URL from your Records server deployment (from Step 6 above).
   :::

2. Update `base_url` (you'll update this again after deployment):
   ```json
   "base_url": "https://multipaz-openid4vci-server-971523157550.us-central1.run.app"
   ```
   
   :::warning ⚠️ Important
   Replace this with your own Cloud Run deployment URL after deploying the server
   :::

### **Step 2: Create Dockerfile**

:::tip 💡 Cloud Shell
If you haven't already, activate Cloud Shell from the Google Cloud Run console by clicking "Activate Cloud Shell" (or press `G` then `S` for keyboard shortcut) to run the commands below.
:::

Create a Dockerfile for the OpenID4VCI server in the `multipaz-openid4vci-server` directory:

```bash
mkdir -p multipaz-openid4vci-server && cat > multipaz-openid4vci-server/Dockerfile <<'EOF'
FROM eclipse-temurin:17-jre
WORKDIR /app
COPY app.jar app.jar
# Cloud Run sets PORT environment variable; pass it to the server using -param format
CMD ["sh","-c","java -jar app.jar -param server_port=${PORT:-8080}"]
EOF
```

**Command Explanation:**
- `mkdir -p multipaz-openid4vci-server`: Creates a directory named `multipaz-openid4vci-server` (the `-p` flag creates parent directories if needed and doesn't error if the directory already exists)
- `cat > multipaz-openid4vci-server/Dockerfile <<'EOF'`: Creates a file called `Dockerfile` inside `multipaz-openid4vci-server` and writes everything until `EOF` into that file
  - The `<<'EOF'` syntax is a "here document" that allows multi-line input
  - The single quotes around `EOF` prevent variable expansion in the content

**Dockerfile Contents Explanation:**
- `FROM eclipse-temurin:17-jre`: Uses Java 17 JRE base image (matches the server's Java version requirement)
- `WORKDIR /app`: Sets the working directory inside the container
- `COPY app.jar app.jar`: Copies the fat JAR file into the container
- `CMD`: Runs the JAR with the PORT environment variable passed as a parameter
  - Note: Uses `-param server_port=` format (not `--server.port=`) because this is a Ktor server
  - `${PORT:-8080}` uses Cloud Run's PORT environment variable, defaulting to 8080 if not set

### **Step 3: Build the Fat JAR**

Build the fat JAR file that includes all dependencies:

```bash
./gradlew :multipaz-openid4vci-server:buildFatJar
```

**What this does:**
- Compiles the Kotlin code
- Packages all dependencies into a single JAR file
- Includes the configuration files (including `default_configuration.json` with the updated `system_of_record_url`)
- Outputs the JAR to `multipaz-openid4vci-server/build/libs/multipaz-openid4vci-server-all.jar`

**Note:** The Ktor Gradle plugin creates a fat JAR named `multipaz-openid4vci-server-all.jar`. We need to rename it to `app.jar` because the Dockerfile expects `app.jar`.

### **Step 4: Prepare for Cloud Build**

Upload the JAR file to Cloud Shell:

1. In the Cloud Shell terminal, click on the three-dot "More" menu icon (⋮) in the top right
2. Select **Upload** from the menu
3. A file selection dialog will open. Navigate to and select your `app.jar` file 
4. The file will be uploaded to your home directory (e.g., `/home/YOUR-PROJECT-ID/multipaz-openid4vci-server`)
   - **Note:** `YOUR-PROJECT-ID` is a placeholder - replace it with your actual project name or username



**Directory structure should look like:**
```
multipaz-openid4vci-server/
├── Dockerfile
└── app.jar
```

### **Step 5: Build Docker Image**

Build the Docker image using Google Cloud Build:

```bash
gcloud builds submit multipaz-openid4vci-server --tag gcr.io/YOUR-PROJECT-ID/multipaz-openid4vci-server
```

**Explanation:**
- `gcloud builds submit`: Submits a build to Google Cloud Build
- `multipaz-openid4vci-server`: The directory containing the Dockerfile and JAR file
- `--tag`: Tags the resulting image with the specified name
- `gcr.io/YOUR-PROJECT-ID/`: Your GCP project's Container Registry path
  - Replace `YOUR-PROJECT-ID` with your actual GCP project ID

**What happens:**
1. Cloud Build reads the Dockerfile
2. Builds a Docker image containing the JAR file
3. Pushes the image to Google Container Registry
4. The image is ready to be deployed to Cloud Run

### **Step 6: Deploy to Cloud Run**

Deploy the containerized application to Cloud Run:

```bash
gcloud run deploy multipaz-openid4vci-server \
  --image gcr.io/YOUR-PROJECT-ID/multipaz-openid4vci-server \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated
```

**Parameters explained:**
- `--image`: Specifies the Docker image to deploy (from Step 5)
- `--platform managed`: Uses Google's fully managed Cloud Run platform
- `--region us-central1`: Deploys to the specified region
  - Choose a region close to your users for better performance
- `--port`: (Optional) Specifies the port your service listens on
  - Defaults to 8080 if not specified (Cloud Run's default)
  - Only needed if your service uses a different port (e.g., `--port 9090`)
  - Must match the `server_port` in your configuration file
- `--allow-unauthenticated`: Makes the service publicly accessible
  - Remove this flag if you want to require authentication

**After deployment:**
- Cloud Run will provide a URL like: `https://multipaz-openid4vci-server-XXXXX.us-central1.run.app`
- Update the `base_url` in your configuration file with this URL
- Rebuild and redeploy if you need to update the base URL

---

## **Verifying Deployment**

After deployment, verify both servers are working:

1. **Records Server**: Visit `https://YOUR-RECORDS-SERVER-URL`
   - You should see the State Registry interface
   - Should redirect to `/index.html` without redirecting to localhost
   - Login with the admin password: `multipaz-records`

2. **OpenID4VCI Server**: Visit `https://YOUR-OPENID4VCI-SERVER-URL`
   - Should redirect to `/index.html` without redirecting to localhost

---

## **Troubleshooting**

### **Issue: Server redirects to localhost**

**Solution:** Ensure `base_url` is set correctly in `default_configuration.json` and rebuild the JAR.

### **Issue: Port binding errors**

**Solution:** The Dockerfile correctly passes the PORT environment variable. Ensure Cloud Run is setting the PORT variable (it does by default).

### **Issue: Cannot connect to Records server**

**Solution:** 
- Verify the Records server is deployed and accessible
- Check that `system_of_record_url` in OpenID4VCI server matches the Records server URL
- Ensure both servers are in the same region or have proper network access

### **Issue: Build fails with "app.jar not found"**

**Solution:** Ensure you've copied the JAR file to the deployment directory before running `gcloud builds submit`.

---


## **Summary**

In this tutorial, you learned:

1. **Configuration changes** made in [this commit](https://github.com/hanluOMH/identity-credential/commit/bd51ad7dc8fd128491da7dff709e7f36eda30330) to prepare servers for Cloud Run
2. **How to build fat JARs** that include all dependencies
3. **How to create Dockerfiles** for containerizing the servers
4. **How to build and deploy** to Google Cloud Run
5. **How to connect** the OpenID4VCI server to the Records server

The servers are now deployed and ready to issue verifiable credentials based on identity data stored in the Records server.

