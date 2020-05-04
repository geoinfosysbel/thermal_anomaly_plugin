from PyQt5.QtCore import QUrl, QUrlQuery, QDateTime
from qgis.PyQt.QtCore import pyqtSignal, QObject, Qt
from PyQt5 import QtNetwork
from PyQt5.QtNetwork import QNetworkRequest, QNetworkReply
import json

json_resp = "{\
   \"currentPage\": 0,\
  \"pageCount\": 0,\
  \"pageSize\": 0,\
  \"allItemsCount\": 0,\
  \"items\": [\
   {   \"coordinatesWKT\":      \"POINT(39.17698 44.81506)\",\
    \"shootingDateTime\":      \"2020-04-09T10:20:41 +00:00\",\
    \"temperature\":     338.5,\
    \"pixelSizeInDirection\":     0.4,\
    \"pixelSizeAcross\":     0.4,\
    \"thermalPower\":     2.4,\
    \"baseResourceId\":      \"efab7fee-ed6d-3384-8a3f-e220ebdcd29d\",\
    \"id\":      \"c494a9bb-535d-4ba5-bf25-96594a4a3979\",\
    \"updated\":      \"2020-04-09T10:39:42 +00:00\",\
    \"satellite\":      \"j01\"\
  },\
   {    \"coordinatesWKT\":      \"POINT(39.19708 44.87296)\",\
    \"shootingDateTime\":      \"2020-04-09T10:20:43 +00:00\",\
    \"temperature\":     332.1,\
    \"pixelSizeInDirection\":     0.4,\
    \"pixelSizeAcross\":     0.4,\
    \"thermalPower\":     1.8,\
    \"baseResourceId\":      \"efab7fee-ed6d-3384-8a3f-e220ebdcd29d\",\
    \"id\":      \"40c5ebaa-bf04-4e20-aa3c-3720019b4660\",\
    \"updated\":      \"2020-04-09T10:39:42 +00:00\",\
    \"satellite\":      \"j01\"\
  },\
   { \"coordinatesWKT\":      \"POINT(39.19396 44.87448)\",\
    \"shootingDateTime\":      \"2020-04-09T10:20:43 +00:00\",\
    \"temperature\":     336.3,\
    \"pixelSizeInDirection\":     0.4,\
    \"pixelSizeAcross\":     0.4,\
    \"thermalPower\":     2.7,\
    \"baseResourceId\":      \"efab7fee-ed6d-3384-8a3f-e220ebdcd29d\",\
    \"id\":      \"6ae54f8d-b012-48e5-bc78-92795c3a38a3\",\
    \"updated\":      \"2020-04-09T10:39:42 +00:00\",\
    \"satellite\":      \"j01\"\
  },\
   {\"coordinatesWKT\":      \"POINT(38.93195 44.84155)\",\
    \"shootingDateTime\":      \"2020-04-09T10:20:43 +00:00\",\
    \"temperature\":     333.5,\
    \"pixelSizeInDirection\":     0.4,\
    \"pixelSizeAcross\":     0.4,\
    \"thermalPower\":     5,\
    \"baseResourceId\":      \"efab7fee-ed6d-3384-8a3f-e220ebdcd29d\",\
    \"id\":      \"b5e9f3c5-77cd-4f3e-bbbb-4ad23fc98274\",\
    \"updated\":      \"2020-04-09T10:39:42 +00:00\",\
    \"satellite\":      \"j01\"\
  },\
   {\"coordinatesWKT\":      \"POINT(40.37091 45.04358)\",\
    \"shootingDateTime\":      \"2020-04-09T10:20:43 +00:00\",\
    \"temperature\":     349.9,\
    \"pixelSizeInDirection\":     0.4,\
    \"pixelSizeAcross\":     0.4,\
    \"thermalPower\":     10.6,\
    \"baseResourceId\":      \"efab7fee-ed6d-3384-8a3f-e220ebdcd29d\",\
    \"id\":      \"9dad1820-521c-454d-a962-387aaec02d19\",\
    \"updated\":      \"2020-04-09T10:39:42 +00:00\",\
    \"satellite\":      \"j01\"\
  },\
   {\"coordinatesWKT\":      \"POINT(41.69026 45.2239)\",\
    \"shootingDateTime\":      \"2020-04-09T10:20:43 +00:00\",\
    \"temperature\":     343.5,\
    \"pixelSizeInDirection\":     0.5,\
    \"pixelSizeAcross\":     0.4,\
    \"thermalPower\":     6.2,\
    \"baseResourceId\":      \"efab7fee-ed6d-3384-8a3f-e220ebdcd29d\",\
    \"id\":      \"401f2650-8b4e-444f-811e-25c502323d35\",\
    \"updated\":      \"2020-04-09T10:39:42 +00:00\",\
    \"satellite\":      \"j01\"\
  },\
   {\"coordinatesWKT\":      \"POINT(41.68451 45.22325)\",\
    \"shootingDateTime\":      \"2020-04-09T10:20:43 +00:00\",\
    \"temperature\":     344.2,\
    \"pixelSizeInDirection\":     0.5,\
    \"pixelSizeAcross\":     0.4,\
    \"thermalPower\":     6.2,\
    \"baseResourceId\":      \"efab7fee-ed6d-3384-8a3f-e220ebdcd29d\",\
    \"id\":      \"3fdbda0c-ca51-484b-b512-7aa0a38050e7\",\
    \"updated\":      \"2020-04-09T10:39:42 +00:00\",\
    \"satellite\":      \"j01\"\
  },\
   {\"coordinatesWKT\":      \"POINT(41.68921 45.22744)\",\
    \"shootingDateTime\":      \"2020-04-09T10:20:43 +00:00\",\
    \"temperature\":     347.2,\
    \"pixelSizeInDirection\":     0.5,\
    \"pixelSizeAcross\":     0.4,\
    \"thermalPower\":     6.2,\
    \"baseResourceId\":      \"efab7fee-ed6d-3384-8a3f-e220ebdcd29d\",\
    \"id\":      \"f3f68220-713d-40be-bbf5-c605d8a7e3f0\",\
    \"updated\":      \"2020-04-09T10:39:42 +00:00\",\
    \"satellite\":      \"j01\"\
  },\
   {\"coordinatesWKT\":      \"POINT(38.91422 44.94209)\",\
    \"shootingDateTime\":      \"2020-04-09T10:20:45 +00:00\",\
    \"temperature\":     333.8,\
    \"pixelSizeInDirection\":     0.4,\
    \"pixelSizeAcross\":     0.4,\
    \"thermalPower\":     1.8,\
    \"baseResourceId\":      \"efab7fee-ed6d-3384-8a3f-e220ebdcd29d\",\
    \"id\":      \"9d72a06c-56a4-4b37-989a-1d4543d38939\",\
    \"updated\":      \"2020-04-09T10:39:42 +00:00\",\
    \"satellite\":      \"j01\"\
  },\
   {\"coordinatesWKT\":      \"POINT(38.39421 44.88752)\",\
    \"shootingDateTime\":      \"2020-04-09T10:20:45 +00:00\",\
    \"temperature\":     335.5,\
    \"pixelSizeInDirection\":     0.4,\
    \"pixelSizeAcross\":     0.4,\
    \"thermalPower\":     2.7,\
    \"baseResourceId\":      \"efab7fee-ed6d-3384-8a3f-e220ebdcd29d\",\
    \"id\":      \"8e2d890f-5b58-467a-aed0-0f79f7443754\",\
    \"updated\":      \"2020-04-09T10:39:42 +00:00\",\
    \"satellite\":      \"j01\"\
  },\
   {\"coordinatesWKT\":      \"POINT(26.15532 42.35264)\",\
    \"shootingDateTime\":      \"2020-04-09T10:20:43 +00:00\",\
    \"temperature\":     328.8,\
    \"pixelSizeInDirection\":     0.4,\
    \"pixelSizeAcross\":     0.6,\
    \"thermalPower\":     3.2,\
    \"baseResourceId\":      \"efab7fee-ed6d-3384-8a3f-e220ebdcd29d\",\
    \"id\":      \"6087edb6-8098-4fd4-95c6-9b17f72d9f82\",\
    \"updated\":      \"2020-04-09T10:39:42 +00:00\",\
    \"satellite\":      \"j01\"\
  },\
   {\"coordinatesWKT\":      \"POINT(26.15122 42.35151)\",\
    \"shootingDateTime\":      \"2020-04-09T10:20:45 +00:00\",\
    \"temperature\":     326.3,\
    \"pixelSizeInDirection\":     0.4,\
    \"pixelSizeAcross\":     0.6,\
    \"thermalPower\":     4.2,\
    \"baseResourceId\":      \"efab7fee-ed6d-3384-8a3f-e220ebdcd29d\",\
    \"id\":      \"c5365d2a-a415-4fb8-9c7c-70e109e0c4c5\",\
    \"updated\":      \"2020-04-09T10:39:42 +00:00\",\
    \"satellite\":      \"j01\"\
  },\
   {\"coordinatesWKT\":      \"POINT(41.94714 45.50929)\",\
    \"shootingDateTime\":      \"2020-04-09T10:20:46 +00:00\",\
    \"temperature\":     331.3,\
    \"pixelSizeInDirection\":     0.5,\
    \"pixelSizeAcross\":     0.4,\
    \"thermalPower\":     13,\
    \"baseResourceId\":      \"efab7fee-ed6d-3384-8a3f-e220ebdcd29d\",\
    \"id\":      \"7145d577-12c4-4dbb-b660-91da01d286e9\",\
    \"updated\":      \"2020-04-09T10:39:42 +00:00\",\
    \"satellite\":      \"j01\"\
  },\
   {\"coordinatesWKT\":      \"POINT(41.94115 45.50861)\",\
    \"shootingDateTime\":      \"2020-04-09T10:20:46 +00:00\",\
    \"temperature\":     351.4,\
    \"pixelSizeInDirection\":     0.5,\
    \"pixelSizeAcross\":     0.4,\
    \"thermalPower\":     13,\
    \"baseResourceId\":      \"efab7fee-ed6d-3384-8a3f-e220ebdcd29d\",\
    \"id\":      \"f4aab47c-6f20-4869-ac89-9a95c8bef8ee\",\
    \"updated\":      \"2020-04-09T10:39:42 +00:00\",\
    \"satellite\":      \"j01\"\
  },\
   {\"coordinatesWKT\":      \"POINT(38.30169 45.03778)\",\
    \"shootingDateTime\":      \"2020-04-09T10:20:46 +00:00\",\
    \"temperature\":     332.2,\
    \"pixelSizeInDirection\":     0.4,\
    \"pixelSizeAcross\":     0.4,\
    \"thermalPower\":     2.7,\
    \"baseResourceId\":      \"efab7fee-ed6d-3384-8a3f-e220ebdcd29d\",\
    \"id\":      \"e275c4e1-0426-4876-a81b-e181fde42bfc\",\
    \"updated\":      \"2020-04-09T10:39:42 +00:00\",\
    \"satellite\":      \"j01\"\
  },\
   {\"coordinatesWKT\":      \"POINT(41.92839 45.51087)\",\
    \"shootingDateTime\":      \"2020-04-09T10:20:46 +00:00\",\
    \"temperature\":     332.6,\
    \"pixelSizeInDirection\":     0.5,\
    \"pixelSizeAcross\":     0.4,\
    \"thermalPower\":     7.5,\
    \"baseResourceId\":      \"efab7fee-ed6d-3384-8a3f-e220ebdcd29d\",\
    \"id\":      \"0961f9d9-729f-4760-8cfa-5dd04a3da26d\",\
    \"updated\":      \"2020-04-09T10:39:42 +00:00\",\
    \"satellite\":      \"j01\"\
  },\
   {\"coordinatesWKT\":      \"POINT(40.9144 45.42377)\",\
    \"shootingDateTime\":      \"2020-04-09T10:20:48 +00:00\",\
    \"temperature\":     332.9,\
    \"pixelSizeInDirection\":     0.4,\
    \"pixelSizeAcross\":     0.4,\
    \"thermalPower\":     7.8,\
    \"baseResourceId\":      \"efab7fee-ed6d-3384-8a3f-e220ebdcd29d\",\
    \"id\":      \"fecf2324-63b9-41a1-b69b-19291c035120\",\
    \"updated\":      \"2020-04-09T10:39:42 +00:00\",\
    \"satellite\":      \"j01\"\
  },\
   {\"coordinatesWKT\":      \"POINT(40.91796 45.42482)\",\
    \"shootingDateTime\":      \"2020-04-09T10:20:48 +00:00\",\
    \"temperature\":     332.2,\
    \"pixelSizeInDirection\":     0.4,\
    \"pixelSizeAcross\":     0.4,\
    \"thermalPower\":     5.8,\
    \"baseResourceId\":      \"efab7fee-ed6d-3384-8a3f-e220ebdcd29d\",\
    \"id\":      \"6e5bf88e-be36-41dc-89e9-291622bd303b\",\
    \"updated\":      \"2020-04-09T10:39:42 +00:00\",\
    \"satellite\":      \"j01\"\
  },\
   {\"coordinatesWKT\":      \"POINT(38.64822 45.13165)\",\
    \"shootingDateTime\":      \"2020-04-09T10:20:48 +00:00\",\
    \"temperature\":     337.2,\
    \"pixelSizeInDirection\":     0.4,\
    \"pixelSizeAcross\":     0.4,\
    \"thermalPower\":     3.8,\
    \"baseResourceId\":      \"efab7fee-ed6d-3384-8a3f-e220ebdcd29d\",\
    \"id\":      \"c8bdd674-ceeb-4ddd-b53c-2c8fcb0d0b41\",\
    \"updated\":      \"2020-04-09T10:39:42 +00:00\",\
    \"satellite\":      \"j01\"\
  },\
   {\"coordinatesWKT\":      \"POINT(43.49347 45.7529)\",\
    \"shootingDateTime\":      \"2020-04-09T10:20:48 +00:00\",\
    \"temperature\":     330.8,\
    \"pixelSizeInDirection\":     0.5,\
    \"pixelSizeAcross\":     0.4,\
    \"thermalPower\":     3.9,\
    \"baseResourceId\":      \"efab7fee-ed6d-3384-8a3f-e220ebdcd29d\",\
    \"id\":      \"30bb5740-3697-4483-9091-f72ba7bd1fef\",\
    \"updated\":      \"2020-04-09T10:39:42 +00:00\",\
    \"satellite\":      \"j01\"\
  }\
  ]\
 }"

TAKE = 1000
AUTH_URL = "https://meteoeye.gis.by/oauth/connect/token"
"""
В качестве MIME-типа использовать Content-Type = multipart/form-data, 
а в Body передавать следующие параметры: 
    grant_type = client_credentials 
    scope = read:Resources:base 
    client_id = email 
    client_secret = key 
Далее требуется передавать полученный токен аутентификации при каждом запросе 
в заголовке Authorization.
"""
THERMAL_ANOMALY_URL = "https://meteoeye.gis.by/api/Resources/hotspots"
"""
  request parameters:
  _take:          int (required),
  _skip:          int (required),
  _sort:          array[string],
  _lastUpdated:   array[string],
  _id:            array[string],
  shooting:       array[string],
  baseResourceId: array[string],
  polygon:        array[string],
  satellite:      array[string]
"""
"""
  response header
  content-length: 0 
  date: Thu, 16 Apr 2020 10:09:01 GMT 
  server: nginx 
  status: 401 
  strict-transport-security: max-age=2592000 
  www-authenticate: Bearer
"""

"""
  response example
  {
    "currentPage": 0,
    "pageCount": 0,
    "pageSize": 0,
    "allItemsCount": 0,
    "items": [
      {
        "coordinatesWKT": "string",
        "shootingDateTime": "2020-04-16T11:56:39.816Z",
        "temperature": 0,
        "pixelSizeInDirection": 0,
        "pixelSizeAcross": 0,
        "thermalPower": 0,
        "baseResourceId": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
        "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
        "updated": "2020-04-16T11:56:39.816Z",
        "satellite": "terra"
      }
    ]
  }
"""


class DataRequest(QObject):

    requestFinished = pyqtSignal([list, bool, bool, str])
    authorizationStarted = pyqtSignal()
    authorizationFinished = pyqtSignal([bool])

    def __init__(self):
        super().__init__()
        self.__authReply = None
        self.__accessToken = None
        self.__accessTokenExpires = QDateTime.currentDateTime()
        self.__manager = QtNetwork.QNetworkAccessManager()

    def isAuthorized(self):
        return self.__accessToken is not None and self.__accessTokenExpires > QDateTime.currentDateTime()

    def authRequest(self, client_id, client_secret, page=None, last_update=None, polygon=None):
        print("Authorization...")
        self.authorizationStarted.emit()
        url = QUrl(AUTH_URL)
        url_query = QUrlQuery()
        url_query.addQueryItem("grant_type", "client_credentials")
        url_query.addQueryItem("scope", "read:Resources:hotspots")
        url_query.addQueryItem("client_id", client_id)
        url_query.addQueryItem("client_secret", client_secret)
        url.setQuery(url_query)

        request = QtNetwork.QNetworkRequest()
        request.setHeader(QNetworkRequest.ContentTypeHeader, "application/json".encode())
        request.setUrl(url)
        self.__authReply = self.__manager.post(request, url_query.toString(QUrl.FullyEncoded).encode())
        self.__authReply.finished.connect(lambda: self.__auth_request_finished(client_id, client_secret, page, last_update, polygon))

    def __auth_request_finished(self, client_id, client_secret, page=None, last_update=None, polygon=None):
        if self.__authReply is None or self.__authReply.error() != QtNetwork.QNetworkReply.NoError:
            self.authorizationFinished.emit(False)
            print("auth error: " + self.__error_string(self.__authReply.error()))
            print(str(self.__authReply.readAll(), 'utf-8'))
            print(self.__authReply.url())
            headers = self.__authReply.rawHeaderList()
            for key in headers:
                print(key, '->', self.__authReply.rawHeader(key))
            self.printKnownHeaders(self.__authReply)
        else:
            self.authorizationFinished.emit(True)
            data = str(self.__authReply.readAll(), 'utf-8')
            try:
                json_string = json.loads(data)
                self.__accessToken = json_string["access_token"]
                self.__accessTokenExpires = QDateTime.currentDateTime().addSecs(int(json_string["expires_in"]))
                # print("auth finished: ", json_string)
                if last_update is not None and polygon is not None:
                    self.__dataRequest(page, client_id, client_secret, last_update, polygon)
            except ValueError as e:
                print(e)

    def dataRequest(self, client_id, client_secret, date_from, date_to, polygon):
        date_format = "yyyy-MM-dd"
        last_update = "eq" + date_from.toString(date_format)
        date_start = date_from.date().addDays(1)
        date_end = date_to.date()
        while date_start <= date_end:
            last_update += "," + date_start.toString(date_format)
            date_start = date_start.addDays(1)

        self.__dataRequest(0, client_id, client_secret, last_update, polygon)

    def __dataRequest(self, page, client_id, client_secret, last_update, polygon):
        print("page=", page)
        print("accessTokenExpires=", self.__accessTokenExpires.toString(Qt.ISODate))

        if not self.isAuthorized():
            self.authRequest(client_id, client_secret, page, last_update, polygon)
            return

        url = QUrl(THERMAL_ANOMALY_URL)
        url_query = QUrlQuery()
        if polygon is not None:
            url_query.addQueryItem("polygon", polygon)
        if last_update is not None:
            url_query.addQueryItem("_lastUpdated", last_update)
        # _take=1000&_skip=0&_lastUpdated=ge2020-04-08T00%3A00%3A00
        url_query.addQueryItem("_take", str(TAKE))
        url_query.addQueryItem("_skip", str(page * TAKE).zfill(1))
        #url.setQuery(url_query)

        # print(url_query.queryItems())

        request = QtNetwork.QNetworkRequest()
        request.setRawHeader(b'Authorization', ('Bearer ' + self.__accessToken).encode())
        request.setHeader(QNetworkRequest.ContentTypeHeader, "application/json".encode())
        request.setUrl(url)
        # print("request: ", url)

        self.dataReply = self.__manager.post(request, url_query.toString(QUrl.FullyEncoded).encode())
        self.dataReply.finished.connect(lambda dr=self.dataReply: self.__data_request_finished(dr, client_id, client_secret, last_update, polygon))

    def __data_request_finished(self, data_reply, client_id, client_secret, last_update, polygon):
        # print("finished with: ", dataReply.url())
        result_items = []
        current_page = 1
        page_count = 1
        msg = None

        if data_reply is None or data_reply.error() != QtNetwork.QNetworkReply.NoError:
            msg = "data error: " + str(data_reply.error()) + ", " + self.__error_string(data_reply.error())
            print(msg)
            print(data_reply.readAll())
            print(data_reply.url())
            headers = data_reply.rawHeaderList()
            for key in headers:
                print(key, '->', data_reply.rawHeader(key))
        else:
            data = str(data_reply.readAll(), 'utf-8')
            if len(data) > 0:
                try:
                    json_string = json.loads(data)
                    if "items" in json_string:
                        result_items = json_string["items"]
                    else:
                        print(data)
                    if "pageCount" in json_string:
                        page_count = int(json_string["pageCount"])
                        if page_count == 0:
                            page_count = 1
                        current_page = int(json_string["currentPage"])
                        if current_page < page_count:
                            print("pageCount=", json_string["pageCount"])
                            print("allItemsCount=", json_string["allItemsCount"])
                            print("currentPage=", json_string["currentPage"])
                            self.__dataRequest(current_page, client_id, client_secret, last_update, polygon)
                        if page_count > 1:
                            msg = str(current_page) + "/" + str(page_count)
                except ValueError as e:
                    print(e)
                    msg = "Wrong server response. Can't be converted to json"
                    # print(data)
            else:
                print(type(data))
                print(data_reply.readAll())
                print(data_reply.error())
        headers = data_reply.rawHeaderList()
        for key in headers:
            print(key, '->', data_reply.rawHeader(key))
        self.printKnownHeaders(data_reply)
        self.requestFinished.emit(result_items, (page_count > 1 and current_page > 1),
                                  (page_count == current_page),
                                  msg)

    def printKnownHeaders(self, reply):
        print("ContentTypeHeader: ", reply.header(QNetworkRequest.ContentTypeHeader))
        print("ContentLengthHeader: ", reply.header(QNetworkRequest.ContentLengthHeader))
        print("LocationHeader: ", reply.header(QNetworkRequest.LocationHeader))
        print("LastModifiedHeader: ", reply.header(QNetworkRequest.LastModifiedHeader))
        print("CookieHeader: ", reply.header(QNetworkRequest.CookieHeader))
        print("SetCookieHeader: ", reply.header(QNetworkRequest.SetCookieHeader))
        print("UserAgentHeader: ", reply.header(QNetworkRequest.UserAgentHeader))
        print("ServerHeader: ", reply.header(QNetworkRequest.ServerHeader))

    def __error_string(self, code):
        if code == QtNetwork.QNetworkReply.NoError:
            return 'no error'
        if code == QNetworkReply.ConnectionRefusedError:
            return 'ConnectionRefusedError'
        if code == QNetworkReply.RemoteHostClosedError:
            return 'RemoteHostClosedError'
        if code == QNetworkReply.HostNotFoundError:
            return 'HostNotFoundError'
        if code == QNetworkReply.TimeoutError:
            return 'TimeoutError'
        if code == QNetworkReply.OperationCanceledError:
            return 'OperationCanceledError'
        if code == QNetworkReply.SslHandshakeFailedError:
            return 'SslHandshakeFailedError'
        if code == QNetworkReply.TemporaryNetworkFailureError:
            return 'TemporaryNetworkFailureError'
        if code == QNetworkReply.NetworkSessionFailedError:
            return 'NetworkSessionFailedError'
        if code == QNetworkReply.BackgroundRequestNotAllowedError:
            return 'BackgroundRequestNotAllowedError'
        if code == QNetworkReply.TooManyRedirectsError:
            return 'TooManyRedirectsError'
        if code == QNetworkReply.InsecureRedirectError:
            return 'InsecureRedirectError'
        if code == QNetworkReply.ProxyConnectionRefusedError:
            return 'ProxyConnectionRefusedError'
        if code == QNetworkReply.ProxyConnectionClosedError:
            return 'ProxyConnectionClosedError'
        if code == QNetworkReply.ProxyNotFoundError:
            return 'ProxyNotFoundError'
        if code == QNetworkReply.ProxyTimeoutError:
            return 'ProxyTimeoutError'
        if code == QNetworkReply.ProxyAuthenticationRequiredError:
            return 'ProxyAuthenticationRequiredError'
        if code == QNetworkReply.ContentAccessDenied:
            return 'ContentAccessDenied'
        if code == QNetworkReply.ContentOperationNotPermittedError:
            return 'ContentOperationNotPermittedError'
        if code == QNetworkReply.ContentNotFoundError:
            return 'ContentNotFoundError'
        if code == QNetworkReply.AuthenticationRequiredError:
            return 'AuthenticationRequiredError'
        if code == QNetworkReply.ContentReSendError:
            return 'ContentReSendError'
        if code == QNetworkReply.ContentConflictError:
            return 'ContentConflictError'
        if code == QNetworkReply.ContentGoneError:
            return 'ContentGoneError'
        if code == QNetworkReply.InternalServerError:
            return 'InternalServerError'
        if code == QNetworkReply.OperationNotImplementedError:
            return 'OperationNotImplementedError'
        if code == QNetworkReply.ServiceUnavailableError:
            return 'ServiceUnavailableError'
        if code == QNetworkReply.ProtocolUnknownError:
            return 'ProtocolUnknownError'
        if code == QNetworkReply.ProtocolInvalidOperationError:
            return 'ProtocolInvalidOperationError'
        if code == QNetworkReply.UnknownNetworkError:
            return 'UnknownNetworkError. An unknown network-related error was detected'
        if code == QNetworkReply.UnknownProxyError:
            return 'UnknownProxyError'
        if code == QNetworkReply.UnknownContentError:
            return 'UnknownContentError'
        if code == QNetworkReply.ProtocolFailure:
            return 'ProtocolFailure. A breakdown in protocol was detected'
        if code == QNetworkReply.UnknownServerError:
            return 'UnknownServerError. An unknown error related to the server response was detected'
        return 'UnknownError. Error with unknown error code'
