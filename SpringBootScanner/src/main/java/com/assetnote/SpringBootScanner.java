package com.assetnote;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.ArrayList;
import java.util.List;

public class SpringBootScanner implements BurpExtension, ScanCheck {

    private MontoyaApi api;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Spring Boot Actuator Hunter");
        api.scanner().registerScanCheck(this);
        api.logging().logToOutput("Spring Boot Scanner loaded. Hunting for /actuator endpoints...");
    }

    @Override
    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint insertionPoint) {
        // We use the base request just to get the Host/Port info
        return doScan(baseRequestResponse.request());
    }

    @Override
    public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse) {
        return AuditResult.auditResult(new ArrayList<>());
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue) {
        return newIssue.name().equals(existingIssue.name()) ?
                ConsolidationAction.KEEP_EXISTING :
                ConsolidationAction.KEEP_BOTH;
    }

    // --- NEW HELPER METHOD FOR RICH REPORTING ---

    /**
     * Helper method to generate the rich HTML report for the Dashboard.
     */
    private AuditIssue createIssue(HttpRequest baseRequest, HttpRequestResponse evidence, String issueName, String path, String grepKeyword) {

        // 1. Construct the Issue Detail (The "What happened")
        String issueDetail = new StringBuilder()
                .append("The application exposes a Spring Boot Actuator endpoint at <b>")
                .append(path)
                .append("</b>.<br><br>")
                .append("This was confirmed by receiving a HTTP 200 OK status code and finding the signature keyword <b>'")
                .append(grepKeyword)
                .append("'</b> in the response body. This leak can expose sensitive configuration details or routing tables.")
                .toString();

        // 2. Construct the Background (The "References")
        String issueBackground = new StringBuilder()
                .append("<b>Vulnerability Information & Remediation:</b><br>")
                .append("Exposing actuator endpoints publicly can lead to serious security risks, including unauthorized configuration changes or sensitive data leaks.<br><br>")
                .append("<b>References:</b><ul>")
                .append("<li><a href='https://www.wiz.io/blog/spring-boot-actuator-misconfigurations'>Wiz: Spring Boot Actuator Misconfigurations</a></li>")
                .append("</ul>")
                .toString();

        // 3. Create the Audit Issue object
        return AuditIssue.auditIssue(
                issueName,                                            // Name
                issueDetail,                                          // Detail (HTML supported)
                "Disable or secure the exposed actuator endpoint in the application configuration (e.g., application.properties or application.yml).", // Remediation
                baseRequest.url(),                                    // Base URL
                AuditIssueSeverity.HIGH,                              // Severity
                AuditIssueConfidence.CERTAIN,                         // Confidence
                issueBackground,                                      // Background (HTML supported)
                null,                                                 // Remediation Background
                AuditIssueSeverity.HIGH,                              // Typical Severity
                evidence                                              // Http Evidence
        );
    }

    // --- MAIN SCAN LOGIC ---

    /**
     * The Main Scanning Logic
     */
    private AuditResult doScan(HttpRequest baseRequest) {
        List<AuditIssue> issues = new ArrayList<>();

        // Format: Path, Signature Keyword, Issue Name
        checkEndpoint(baseRequest, "/actuator/env", "activeProfiles", "Spring Boot Environment Leak", issues);
        checkEndpoint(baseRequest, "/actuator", "_links", "Spring Boot Actuator Discovery", issues);
        checkEndpoint(baseRequest, "/actuator/mappings", "dispatcherServlet", "Spring Boot API Mappings", issues);
        checkEndpoint(baseRequest, "/env", "profiles", "Legacy Spring Boot Env Leak", issues);
        checkEndpoint(baseRequest, "/actuator/gateway/routes", "predicate", "Spring Cloud Gateway Routes Leak", issues);

        return AuditResult.auditResult(issues);
    }

    /**
     * Helper method to check a single endpoint
     */
    private void checkEndpoint(HttpRequest baseRequest, String path, String grepKeyword, String issueName, List<AuditIssue> issues) {

        // FIX: Derive the request from the baseRequest to keep Host/Service info valid
        HttpRequest checkRequest = baseRequest
                .withMethod("GET")
                .withPath(path)
                .withBody(ByteArray.byteArray("")) // Empty body for GET requests
                .withRemovedHeader("Content-Type")
                .withRemovedHeader("Content-Length")
                .withHeader("User-Agent", "Mozilla/5.0 (BugBountyScanner/1.0)");

        // Send it
        HttpRequestResponse responsePair = api.http().sendRequest(checkRequest);
        HttpResponse response = responsePair.response();

        // Check if successful (200 OK) AND contains the signature keyword
        if (response.statusCode() == 200 && response.bodyToString().contains(grepKeyword)) {

            api.logging().logToOutput("[+] FOUND: " + path + " on " + baseRequest.httpService().host());

            // Use the new helper method to generate the detailed issue
            AuditIssue issue = createIssue(baseRequest, responsePair, issueName, path, grepKeyword);
            issues.add(issue);
        }
    }
}