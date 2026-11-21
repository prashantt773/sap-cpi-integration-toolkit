/**
 * ExceptionPayloadLogger.groovy
 * 
 * Purpose: Captures caught Camel exceptions, HTTP response codes, and optional 
 * payload attachments in the SAP CPI Message Processing Log (MPL) without 
 * exposing sensitive headers.
 * 
 * Optional Exchange Properties:
 * - EnablePayloadAttachment (true/false, default: true)
 * - CorrelationKeyHeader (Header name to surface as MPL Custom Header, e.g., "X-Correlation-ID")
 */
def Message processData(Message message) {
    def properties = message.getProperties()
    def headers = message.getHeaders()
    def messageLog = messageLogFactory.getMessageLog(message)

    if (messageLog == null) {
        return message
    }

    // 1. Log Correlation ID as searchable MPL Custom Header
    def correlationHeaderName = properties.get("CorrelationKeyHeader") ?: "SAP_MessageProcessingLogID"
    def correlationValue = headers.get(correlationHeaderName) ?: properties.get(correlationHeaderName)
    if (correlationValue != null) {
        messageLog.addCustomHeaderProperty("CorrelationKey", correlationValue.toString())
    }

    // 2. Extract caught exception details
    def exception = properties.get("CamelExceptionCaught")
    if (exception != null) {
        def errorDetails = new StringBuilder()
        errorDetails.append("Exception Class: ").append(exception.getClass().getName()).append("\n")
        errorDetails.append("Error Message: ").append(exception.getMessage() ?: "No message provided").append("\n")

        // Capture HTTP status/body if HTTP adapter threw the error
        if (exception.metaClass.respondsTo(exception, "getStatusCode")) {
            errorDetails.append("HTTP Status Code: ").append(exception.getStatusCode()).append("\n")
        }
        if (exception.metaClass.respondsTo(exception, "getResponseBody")) {
            errorDetails.append("HTTP Response Body:\n").append(exception.getResponseBody()).append("\n")
        }

        messageLog.addAttachmentAsString("Exception_Details", errorDetails.toString(), "text/plain")
    }

    // 3. Optionally attach current payload for troubleshooting
    def attachPayload = (properties.get("EnablePayloadAttachment") ?: "true").toString().toBoolean()
    if (attachPayload) {
        def body = message.getBody(String)
        if (body != null && !body.trim().isEmpty()) {
            def contentType = headers.get("Content-Type")?.toString()?.contains("xml") ? "application/xml" : "text/plain"
            messageLog.addAttachmentAsString("Failed_Payload", body, contentType)
        }
    }

    return message
}
3. groovy-scripts/SensitiveDataMasker.groovy
Click Add file → Create new file, type groovy-scripts/SensitiveDataMasker.groovy, and paste:

Groovy
import com.sap.gateway.ip.core.customdev.util.Message
import groovy.json.JsonOutput
import groovy.json.JsonSlurper

/**
 * SensitiveDataMasker.groovy
 * 
 * Purpose: Masks sensitive fields (e.g., IBAN, SSN, tokens, passwords) in JSON payloads 
 * before writing diagnostic attachments to SAP CPI Message Processing Logs, while leaving 
 * the actual message body intact for downstream processing.
 * 
 * Exchange Properties:
 * - SensitiveFields: Comma-separated list of JSON keys to mask (default: "password,token,iban,secret,ssn")
 */
def Message processData(Message message) {
    def body = message.getBody(String)
    def messageLog = messageLogFactory.getMessageLog(message)

    if (body == null || body.trim().isEmpty() || messageLog == null) {
        return message
    }

    def rawFields = message.getProperties().get("SensitiveFields") ?: "password,token,iban,secret,ssn"
    def sensitiveKeys = rawFields.toString().split(",").collect { it.trim().toLowerCase() } as Set

    try {
        def parsed = new JsonSlurper().parseText(body)
        def maskedData = maskRecursive(parsed, sensitiveKeys)
        def maskedJson = JsonOutput.prettyPrint(JsonOutput.toJson(maskedData))

        messageLog.addAttachmentAsString("Masked_Diagnostic_Payload", maskedJson, "application/json")
    } catch (Exception e) {
        messageLog.setStringProperty("MaskingWarning", "Skipped JSON masking: payload is not valid JSON.")
    }

    // Return original unmasked message for downstream adapter calls
    return message
}

private def maskRecursive(def node, Set<String> sensitiveKeys) {
    if (node instanceof Map) {
        def result = [:]
        node.each { k, v ->
            if (sensitiveKeys.contains(k.toString().toLowerCase())) {
                result[k] = "***MASKED***"
            } else {
                result[k] = maskRecursive(v, sensitiveKeys)
            }
        }
        return result
    } else if (node instanceof List) {
        return node.collect { item -> maskRecursive(item, sensitiveKeys) }
    }
    return node
}
