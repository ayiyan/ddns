import requests, hmac
from urllib.parse import quote
from urllib.parse import urlencode
from hashlib import sha1
from datetime import datetime
from base64 import encodestring
from random import randint

class modif_dns:
    def post(self, Aliyun_API):
        url = 'https://alidns.aliyuncs.com/'
        print(Aliyun_API)
        Commit = requests.post(url, data=Aliyun_API)
        print(Commit)
        print(Commit.text)

    def get(self, Aliyun_API):
        url = 'https://alidns.aliyuncs.com/'
        Aliyun_API = urlencode(Aliyun_API)
        Commit = get(url + Aliyun_API)
        print(Commit)
        print(Commit.text)


class parameter(modif_dns):
    def __init__(self, Api_Message):
        Aliyun_API = {
            'Format': 'JSON',
            'Version': '2015-01-09',
            'SignatureMethod': 'HMAC-SHA1',
            'Timestamp': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
            'SignatureVersion': '1.0',
            'SignatureNonce': randint(0, 99999999999999),
        }

        for key in Api_Message.keys():
            if Api_Message[key] != 'AccessKeySecret':
               Aliyun_API[key] = Api_Message[key]

        Sorte_Info = sorted( Aliyun_API.items(), key=lambda x: x[0])
        canstring = ''
        for k, v in Sorte_Info:
            canstring += '&' + self.percentEncode(k) + '=' + self.percentEncode(v)
        StringToSign = 'POST&%2F&' + self.percentEncode(canstring[1:])
        h = hmac.new((Api_Message['AccessKeySecret'] + "&").encode('ASCII'), StringToSign.encode('ASCII'), sha1)
        Signature = encodestring(h.digest()).strip()
        Aliyun_API['Signature'] = Signature
        print(Aliyun_API)
        modif_dns.post(self, Aliyun_API)


    def percentEncode(self, encodeStr):
        encodeStr = str(encodeStr)
        res = quote(encodeStr.encode('utf-8'), '')
        res = res.replace('+', '%20')
        res = res.replace('*', '%2A')
        res = res.replace('%7E', '~')
        return res

if __name__ == '__main__':
    def message():
        Api_Message = {
            'RecordId': '!@#$%^^&*',
            'AccessKeyId': '!@#$%^^&*',
            'Action': 'UpdateDomainRecord',
            'DomainName': '!@#$%^^&*',
            'RR': 'ddns',
            'Type': 'A',
            'Value': '!@#$%^^&*',
            'AccessKeySecret': '!@#$%^^&*'
        }
        return Api_Message

    parameter(message())
