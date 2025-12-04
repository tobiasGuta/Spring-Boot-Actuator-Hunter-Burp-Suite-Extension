# Spring Boot Actuator Hunter (Burp Suite Extension)

![Java](https://img.shields.io/badge/Java-ED8B00?style=for-the-badge&logo=java&logoColor=white) ![Burp Suite](https://img.shields.io/badge/Burp_Suite-FF6633?style=for-the-badge&logo=burpsuite&logoColor=white) ![Security](https://img.shields.io/badge/Cybersecurity-Bug_Bounty-red?style=for-the-badge)

A lightweight, high-speed Burp Suite extension designed to detect exposed **Spring Boot Actuator** endpoints. It automatically fuzzes target applications for sensitive administrative paths that can leak environment variables, API mappings, and routing configurations.

## Features

* **Automated Path Fuzzing:** Checks for multiple high-value endpoints on every scan.
* **Signature-Based Detection:** Uses specific JSON keywords (e.g., `activeProfiles`, `predicate`, `dispatcherServlet`) to confirm vulnerabilities and eliminate false positives.
* **High-Value Targets:** Specifically targets endpoints that lead to Critical/High impact findings in bug bounties:
    * `/actuator/env` (Credentials & Secrets)
    * `/actuator/gateway/routes` (Spring Cloud Gateway Routing Table)
    * `/actuator/mappings` (Internal API Structure)
* **Active Scanning:** Integrates directly into Burp's scanner workflow.

## Installation

1.  Download the latest JAR file from the **Releases** page (or build it yourself).
2.  Open **Burp Suite**.
3.  Navigate to **Extensions** > **Installed**.
4.  Click **Add**.
5.  Select **Extension type: Java**.
6.  Select the `SpringBootScanner-1.0-SNAPSHOT.jar` file.

## Usage

1.  Navigate to any Spring Boot application in Burp Suite.
2.  Right-click on a request (e.g., `GET /`) in the **Proxy History** or **Repeater**.
3.  Select **Extensions** > **Spring Boot Actuator Hunter** > **Scan**.
4.  Check the **Dashboard** or **Target** tab for alerts.

## Detected Endpoints

The scanner currently checks for the following paths:

| Endpoint | Impact | Signature Keyword |
| :--- | :--- | :--- |
| `/actuator/env` | **High**: Leaks environment variables, AWS keys, DB passwords. | `activeProfiles` |
| `/actuator/gateway/routes` | **High**: Leaks internal microservice routes and backend architecture. | `predicate` |
| `/actuator/mappings` | **Medium**: Lists all available API endpoints and controllers. | `dispatcherServlet` |
| `/actuator` | **Info**: Discovery endpoint listing other available actuators. | `_links` |
| `/env` | **High**: Legacy (Spring Boot 1.x) environment leak. | `profiles` |

## Building from Source

To build this project, you need **Java JDK 21+**.

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/tobiasGuta/Spring-Boot-Actuator-Hunter-Burp-Suite-Extension.git
    cd Spring-Boot-Actuator-Hunter-Burp-Suite-Extension
    ```

2.  **Build with Gradle:**
    ```bash
    # Linux/Mac
    ./gradlew clean build

    # Windows
    gradlew.bat clean build
    ```

3.  **Locate the JAR:**
    The compiled extension will be located in:
    `build/libs/SpringBootScanner-1.0-SNAPSHOT.jar`

## Development

You can easily add new endpoints to the scanner by modifying the `doScan` method in `SpringBootScanner.java`.

```java
// Example: Adding a check for Loggers
checkEndpoint(baseRequest, "/actuator/loggers", "levels", "Spring Boot Loggers", issues);
