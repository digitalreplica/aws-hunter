from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from array import array

GREP_STRING = "AccessKeyId"
GREP_STRING_BYTES = bytearray(GREP_STRING)

##### Helper Functions #####
def _consolidateDuplicateIssues(existingIssue, newIssue):
    # This method is called when multiple issues are reported for the same URL
    # path by the same extension-provided check. The value we return from this
    # method determines how/whether Burp consolidates the multiple issues
    # to prevent duplication
    #
    # Since the issue name is sufficient to identify our issues as different,
    # if both issues have the same name, only report the existing issue
    # otherwise report both issues
    if existingIssue.getIssueName() == newIssue.getIssueName():
        return -1
    return 0


def _get_matches(helpers, response, match):
    ''' helper method to search a response for occurrences of a literal match
        string and return a list of start/end offsets
    '''
    matches = []
    start = 0
    reslen = len(response)
    matchlen = len(match)
    while start < reslen:
        start = helpers.indexOf(response, match, True, start, reslen)
        if start == -1:
            break
        matches.append(array('i', [start, start + matchlen]))
        start += matchlen

    return matches

##### BurpExtender Class #####
class BurpExtender(IBurpExtender):
    ''' implement IBurpExtender
    '''
    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self.callbacks = callbacks

        # obtain an extension helpers object
        self.helpers = callbacks.getHelpers()

        # set our extension name
        callbacks.setExtensionName("AWS Hunter")
        print("AWS Hunter")

        # Register Scanner Checks
        callbacks.registerScannerCheck(AwsSecrets(self.callbacks, self.helpers))
        callbacks.registerScannerCheck(FindAwsEndpoints(self.callbacks, self.helpers))

##### Scanner Checks #####
class AwsSecrets(IScannerCheck):
    def __init__(self, callbacks, helpers):
        print("AwsSecrets: setting callbacks to {}".format(callbacks))
        self.callbacks = callbacks
        self.helpers = helpers

    def doPassiveScan(self, baseRequestResponse):
        title = None
        description = None
        severity = None

        # First look for access keys
        access_key_matches = []
        for token in ["AccessKeyId"]:
            token_bytes = bytearray(token)
            access_key_matches = access_key_matches + _get_matches(
                self.helpers, baseRequestResponse.getResponse(), token_bytes)
            if (len(access_key_matches) > 0):
                print("AWS access key found")
                title = "AWS access key found"
                description = "An AWS Access Key was detected. By itself, this likely indicates readonly access to an S3 object."
                severity = "Medium"

        secret_key_matches = []
        for token in ["SecretAccessKey", "SessionToken"]:
            token_bytes = bytearray(token)
            secret_key_matches = secret_key_matches + _get_matches(
                self.helpers, baseRequestResponse.getResponse(), token_bytes)
            if (len(secret_key_matches) > 0):
                print("AWS secret key found")
                title = "AWS secret key found"
                description = "An AWS Secret Key was detected."
                severity = "High"

        # Report if needed
        if title:
            matches = access_key_matches + secret_key_matches
            # report the issue
            return [CustomScanIssueBase(
                baseRequestResponse.getHttpService(),
                self.helpers.analyzeRequest(baseRequestResponse).getUrl(),
                [self.callbacks.applyMarkers(baseRequestResponse, None, matches)],
                title,
                description,
                severity)]
        return None

    def doActiveScan(self, baseRequestResponse):
        return None

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        return _consolidateDuplicateIssues(existingIssue, newIssue)

class FindAwsEndpoints(IScannerCheck):
    def __init__(self, callbacks, helpers):
        self.callbacks = callbacks
        self.helpers = helpers

    def doPassiveScan(self, baseRequestResponse):
        title = None
        description = None
        severity = None
        issues = []

        # Request checks
        request_matches = []
        response_matches = []

        for token in [".amazonaws.com"]:
            token_bytes = bytearray(token)
            request_matches = request_matches + _get_matches(
                self.helpers, baseRequestResponse.getRequest(), token_bytes)
            response_matches = response_matches + _get_matches(
                self.helpers, baseRequestResponse.getResponse(), token_bytes)
        if request_matches or response_matches:
            print("AWS Endpoint Found")
            issues.append(AwsEndpointScanIssue(
                baseRequestResponse.getHttpService(),
                self.helpers.analyzeRequest(baseRequestResponse).getUrl(),
                [self.callbacks.applyMarkers(baseRequestResponse, request_matches, response_matches)],
                ))
        return issues

    def doActiveScan(self, baseRequestResponse):
        return None

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        return _consolidateDuplicateIssues(existingIssue, newIssue)

#
# class implementing IScanIssue to hold our custom scan issue details
#
class CustomScanIssueBase (IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity="Low", confidence="Certain"):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity
        self._confidence = confidence

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService

class AwsEndpointScanIssue (CustomScanIssueBase):
    def __init__(self, httpService, url, httpMessages):
        super(CustomScanIssueBase, self).__init__()
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = "AWS endpoint found"
        self._detail = "An endpoint was found ending in .amazonaws.com, indicating that the organization is using an Amazon service."
        self._severity = "Low"
        self._confidence = "Firm"
