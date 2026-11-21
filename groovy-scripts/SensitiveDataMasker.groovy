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
