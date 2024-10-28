from burp import IBurpExtender, IHttpListener
from java.io import PrintWriter

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Automate Token Modification with Debugging")
        callbacks.registerHttpListener(self)
        
        # Set up output for debugging
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            try:
                # Retrieve the HTTP request
                request = messageInfo.getRequest()
                requestInfo = self._helpers.analyzeRequest(request)
                headers = list(requestInfo.getHeaders())

                # Debug: Log original request details
                self._stdout.println("Intercepted Request URL: " + requestInfo.getUrl().toString())
                self._stdout.println("Original Headers:")
                for header in headers:
                    self._stdout.println(header)

                # Modify the Authorization header
                new_headers = []
                modified = False
                for header in headers:
                    if header.startswith("Authorization:"):  # Changed 'startsWith' to 'startswith'
                        new_headers.append("Authorization: Bearer YOUR_NEW_TOKEN_VALUE")
                        modified = True
                        # Debug: Log the change
                        self._stdout.println("Authorization header modified.")
                    else:
                        new_headers.append(header)

                # If no modification was made, log that information
                if not modified:
                    self._stdout.println("No Authorization header found in the request.")

                # Get the body of the request
                body = request[requestInfo.getBodyOffset():]

                # Rebuild the HTTP message with modified headers
                messageInfo.setRequest(self._helpers.buildHttpMessage(new_headers, body))

                # Debug: Log the modified headers
                self._stdout.println("Modified Headers:")
                for header in new_headers:
                    self._stdout.println(header)
                self._stdout.println("------------------------------------------------")
                
            except Exception as e:
                # Log any exception to the error output
                self._stderr.println("Error processing the HTTP message: " + str(e))
                self._stderr.println("------------------------------------------------")
