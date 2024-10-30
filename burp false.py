from burp import IBurpExtender, IHttpListener
from java.io import PrintWriter

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Modify Response for Specific Endpoint")
        callbacks.registerHttpListener(self)
        
        # Set up output for debugging
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Intercept only responses
        if not messageIsRequest:
            try:
                # Check if the request URL matches the specified endpoint
                requestInfo = self._helpers.analyzeRequest(messageInfo)
                url = requestInfo.getUrl().toString()
                
                if "/ff4j/api/ff4j/check/BCON-Exp-DisallowAnonymousWSAccess" in url:
                    # Debug: Log that the endpoint was matched
                    self._stdout.println(f"Intercepted response for URL: {url}")

                    # Get and modify the response body
                    response = messageInfo.getResponse()
                    responseInfo = self._helpers.analyzeResponse(response)
                    bodyOffset = responseInfo.getBodyOffset()
                    body = response[bodyOffset:].tostring()

                    # Check if body contains "true" and replace with "false"
                    modified_body = body.replace("true", "false")
                    
                    # Rebuild the response with modified body
                    new_response = self._helpers.buildHttpMessage(response[:bodyOffset], modified_body)
                    messageInfo.setResponse(new_response)
                    
                    # Debug: Log that the modification was applied
                    self._stdout.println("Response modified from 'true' to 'false'")
                    
            except Exception as e:
                # Log any exception to the error output
                self._stderr.println("Error processing the HTTP message: " + str(e))
                self._stderr.println("------------------------------------------------")
