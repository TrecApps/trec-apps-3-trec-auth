# TrecAuth

* **Current Version:** 0.9.33-alpha
* **Minimum Java:** 21 (since 0.9.24-alpha)

The **TrecAuth** project is a library designed to provide a cloud-agnostic mechanism for providing customized Security 
configuration for Spring Boot applications. It is meant to provide the Spring Boot application with the following features:

* **JPA persistant logins:** Store basic user information in a couple of Databases 
(one to hold basic logon info and another to hold salt info)
* **BCrypt-Hashing:** uses BCrypt-Hashing to store user passwords
* **Cloud-Storage for users:** Support for storing User Information in Azure Storage, Google Cloud Storage, or AWS S3
* **RSA-Encrypted JWT Authentication:** Issues RSA-Encrypted JSON-Web-Tokens that can be used to Authenticate requests
* **Session Management:** JWT tokens store a session ID, which are tracked by the library and can be disabled by the user
* **Brute-Force Mitigation:** Enables locking of accounts if too many failed logins occurred in a short period of time
* **Email/Phone Validation:** Allows users to validate the email and phone numbers they submit (Note: the application will need to perform the verification)
* **Multi-Factor Authentication:** Allows optional Multi-Factor Authentication methods to be applied to a User Account (either through an Authenticator app, or through phone-email)
* **RSA-JWT Key Rotation:** Keys can be rotated and old keys can be set to expire after a certain period of time
* **Field level encryption:** Certain Fields in storage can be encrypted via RSA or AES-GCM encryption (not currently subjected to Key Rotation)

## Set up

To use **TrecAuth** in your project, you'll need to configure your build files:

```groovy
// build.gradle

repositories {
    mavenCentral()

    maven { // where the TrecAuth Dependency is stored
        url azureRepoUrl
        name 'tcMavenRepo'
        credentials {
            username azureRepoUsername
            password azureRepoPassword
        }
    }
}

dependencies {
    
    // The minimum supported lombok on Java 21 is 1.18.30

    implementation 'org.projectlombok:lombok:1.18.36'
    annotationProcessor 'org.projectlombok:lombok:1.18.36'
    // Include the sdk as a dependency

    //Enable Trec-Auth
    implementation 'com.trecapps.auth:TrecAuth:0.9.25-alpha'

    // Other dependencies
}

```

### Spring Web

Main Class
```java
@SpringBootApplication
@ComponentScan(basePackages = {
        "com.trecapps.auth.common.*",   // For all projects 
        "com.trecapps.auth.web.*"       // Spring Web Specific
})
public class Driver {
    public static void main(String[] args)
    {
        ApplicationInsights.attach();
        SpringApplication.run(Driver.class, args);
    }
}
```

Spring Security Configuration

```java
@EnableWebSecurity
@Configuration
@Order(2)
public class SecurityConfig {

    @Autowired
    SecurityConfig(TrecAuthManagerWeb trecAuthManagerWeb1, TrecSecurityContextServlet trecSecurityContext1)
    {
        trecAuthManagerWeb = trecAuthManagerWeb1;
        trecSecurityContext = trecSecurityContext1;
    }
    TrecAuthManagerWeb trecAuthManagerWeb;
    TrecSecurityContextServlet trecSecurityContext;

    @Bean
    protected SecurityFilterChain configure(HttpSecurity security) throws Exception
    {
        security = security.csrf(AbstractHttpConfigurer::disable)
                .cors(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests((req) ->
                        // use `req` to secure endpoints
                        )
                .authenticationManager(trecAuthManagerWeb)
                .securityContext((cust)->
                        cust.securityContextRepository(trecSecurityContext)
                )
                .sessionManagement((cust)-> cust.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        return security.build();
    }

}
```

### Spring Web-flux

Main Class
```java
@SpringBootApplication
@ComponentScan(basePackages = {
        "com.trecapps.auth.common.*",       // For all projects 
        "com.trecapps.auth.webflux.*"       // Spring Webflux Specific
})
@EnableWebFlux
public class Driver {
    public static void main(String[] args)
    {
        ApplicationInsights.attach();
        SpringApplication.run(Driver.class, args);
    }
}
```

Security Config
```java
@EnableWebFluxSecurity
@Configuration
@Order(1)
public class SecurityConfig {

    @Autowired
    SecurityConfig(TrecAccountServiceAsync trecAccountService1,
                   TrecSecurityContextReactive trecSecurityContext1,
                   TrecAuthManagerReactive trecAuthManagerReactive)
    {
        trecAccountService = trecAccountService1;
        trecSecurityContext = trecSecurityContext1;
        this.trecAuthManagerReactive = trecAuthManagerReactive;
    }
    TrecAccountServiceAsync trecAccountService;
    TrecSecurityContextReactive trecSecurityContext;
    TrecAuthManagerReactive trecAuthManagerReactive;

    String[] restrictedEndpoints = {
            // Authenticated endpoints

    };

    String[] verifiedEndpoints = {
            // strictly controlled endpoints
    };

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(
            ServerHttpSecurity http) {

        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .logout(ServerHttpSecurity.LogoutSpec::disable)
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers(restrictedEndpoints).authenticated()
                        .pathMatchers(verifiedEndpoints).hasAuthority("TREC_VERIFIED")
                        .anyExchange().permitAll())
                .authenticationManager(trecAuthManagerReactive)
                .securityContextRepository(trecSecurityContext)

                .build();
    }
}
```

### Note:

This library supports 
1. Verifying authenticated requests
2. Logging in and issuing JWT tokens

for Applications supporting #2, you'll need to perform the following steps

* set `trecauth.login=true` in a properties file. This makes the `TrecAccountServiceAsync` or `TrecAccountService` 
classes available (depending on whether web or webflux is being used)
* Use this class to authenticate the initial username/password login


## Configuration

### JPA Databases

**Note:** required for applications managing login

```properties
trecauth.datasource-primary.url=${DB_URL}
trecauth.datasource-primary.username=${DB_USERNAME}
trecauth.datasource-primary.password=${DB_PASSWORD}
trecauth.datasource-primary.driver-class-name=${DB_DRIVER}

trecauth.datasource-secondary.url=${DB_URL_2}
trecauth.datasource-secondary.username=${DB_USERNAME_2}
trecauth.datasource-secondary.password=${DB_PASSWORD_2}
trecauth.datasource-secondary.driver-class-name=${DB_DRIVER}
```

TrecAuth supports using two databses to seperate password information. The primary database
stores account login information while the second stores salt information

### JWT Key location

There are three officially suported locations where keys can be stored:
* Azure Key Vault
* AWS Secrets Manager
* GCP Secret Manager

#### Using Azure Key Vault

Make sure you have a service Principal that has access to the Key Vault in question. Then set these properties
```properties
# Tell TrecAuth to use Azure Key Vault
trecauth.jwt.key-storage.strategy=AKV

trec.jwt.vault-name=${name of the key vault}

trec.jwt.tenantId=${Entra Tenant used to support the credentials}
trec.jwt.clientId=${Entra Client ID}
trec.jwt.clientSecret=${Entra Client Secret}
```

#### Using AWS Secrets Manager

**Note:** AWS Secrets Manager supports plain text mode and Key-Value mode. TrecAuth uses the latter configuration

```properties
# Tell TrecAuth to use AWS Secrets Manager
trecauth.jwt.key-storage.strategy=AWSSM

trec.jwt.secret=${Name of the Secret being stored}

trec.jwt.region=${AWS Region}
trec.jwt.clientId=${Account ID to authenticate as}
trec.jwt.clientSecret=${Account Secret to authenticate as}
```

#### Using GCP Secret Manager

**Note:** GCP will compel you to use Passwordless authentication. You can download a json file and set the environment variable
`GOOGLE_APPLICATION_CREDENTIALS` to the location of the json file

```properties
# Tell TrecAuth to use GCP Secret Manager
trecauth.jwt.key-storage.strategy=GCPSM

trec.jwt.project=${GCP_PROJECT}
```

#### Key names

The Key names can be specified as such:
```properties
trec.key.public=${name of public key Secret}
trec.key.private=${name of private key secret}

```

### Field Encryption

To configure Field-level encryption:

```properties

trecauth.encryption.strategy=${RSA or AES}

# If using RSA
trecauth.encryptor.rsa.public-name=${Name of the Public Key}
trecauth.encryptor.rsa.private-name=${Name of the Private Key} 

# if using AES
trecauth.encryptor.aes.password=${AES Password}
trecauth.encryptor.aes.salt=${AES Salt}
trecauth.encryptor.aes.iv=${AES IV}

```
If the `trecauth.encryption.strategy` property is left blank, no field-encryption is performed

#### Azure Key Vault

```properties
# Retrieve Key info from Key Vault
trecauth.key-holder.type=azure-key-vault

trecauth.keyvault.name=${name of the key-vault}
trecauth.keyvault.tenantId=${Entra tenant Id}
trecauth.keyvault.clientId=${Entra Client ID}
trecauth.keyvault.clientSecret=${Entra Client Secret}
```

#### AWS Secrets Manager

```properties
# Retrieve Key info from AWS Secrets Manager
trecauth.key-holder.type=aws-secrets-manager

trecauth.secrets-manager.region=${AWS Region}
trecauth.secrets-manager.secret=${Secret Name}
trecauth.secrets-manager.clientName=${Client ID}
trecauth.secrets-manager.clientSecret=${Client Secret}
```

#### GCP Secret Manager

```properties
trecauth.key-holder.type=gcp-secret-manager
trecauth.secret-manager.project=${ID of the GCP Project}
```

### User Storage

This configures the location of the User and Session information

#### Using Azure Storage

```properties
# Set the storage solution to Azure
trecauth.storage.strategy=Azure-key

trecauth.storage.account-name=${STORAGE_ACCOUNT_NAME}
trecauth.storage.account-key=${STORAGE_ACCOUNT_KEY}
trecauth.storage.blob-endpoint=${STORAGE_ACCOUNT_ENDPOINT}
```

#### AWS S3

```properties
# Set the storage solution to AWS S3 (using a key)
trecauth.storage.strategy=AWS-S3-key

trecauth.storage.account-name=${AWS_STORAGE_ACCOUNT_NAME}
trecauth.storage.account-key=${AWS_STORAGE_ACCOUNT_KEY}
trecauth.storage.s3-region=${AWS_USER_REGION}
trecauth.storage.s3-bucket=${AWS_USER_BUCKET}
```

#### GCP Storage

```properties
# Set the storage solution to GCP Storage
trecauth.storage.strategy=GCP-Storage

trecauth.storage.project-id=${GCP_PROJECT}
trecauth.storage.bucket=${GCP_STORAGE_BUCKET}
```

### JWT Key Rotation

**Note:** This feature has only been tested in an Azure Environment

```properties
# Configuration for retrieving a new Key

trecauth.rotate.do-rotate=true
trecauth.rotate.rotate-cron-schedule=0 0 2 ? * SUN *
trecauth.key.version-count=2
```

The following properties enable generating a new key and publishing it to the Key repository:
```properties
trecauth.rotate.do-update=true
trecauth.rotate.update-cron-schedule=0 0 1 ? * SUN *
```

**Note:** Because you might have multiple instances of an application running, it is recommented to 
disable `trecauth.rotate.do-update` and delegate that task to the clouds serverless function


