import asyncio
import requests
import urllib.parse
import random

class TCPSocketConnectChecker:
    def __init__(self, host, port, timeout=10.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.connection_status = None
    def __repr__(self):
        return "{}:{}".format(self.host if self.host.find(":") == -1 else "[" + self.host + "]", self.port)
    async def connect(self):
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(self.host, self.port), self.timeout)
            writer.close()
            await writer.wait_closed()
            self.connection_status = True
            return (True, None)
        except (OSError, asyncio.TimeoutError) as e:
            self.connection_status = False
            return (False, e)

class TorRelayGrabber:
    def __init__(self, timeout=10.0, proxy=None):
        self.timeout = timeout
        self.proxy = {'https': proxy} if proxy else None
        self.log_callback = None

    def _grab(self, url):
        with requests.get(url, timeout=int(self.timeout), proxies=self.proxy) as r:
            return r.json()

    def grab(self, preferred_urls_list=None):
        BASEURL = "https://onionoo.torproject.org/details?type=relay&running=true&fields=fingerprint,or_addresses,country"
        URLS = [BASEURL,
                "https://icors.vercel.app/?" + urllib.parse.quote(BASEURL),
                "https://github.com/ValdikSS/tor-onionoo-mirror/raw/master/details-running-relays-fingerprint-address-only.json",
                "https://bitbucket.org/ValdikSS/tor-onionoo-mirror/raw/master/details-running-relays-fingerprint-address-only.json"]
        if preferred_urls_list:
            for pref_url in preferred_urls_list:
                URLS.insert(0, pref_url)
        for url in URLS:
            try:
                return self._grab(url)
            except Exception as e:
                if self.log_callback:
                    self.log_callback(f"Can't download Tor Relay data from/via {urllib.parse.urlparse(url).hostname}: {e}")

    def grab_parse(self, preferred_urls_list=None):
        grabbed = self.grab(preferred_urls_list)
        if grabbed:
            grabbed = grabbed["relays"]
        return grabbed

class TorRelay:
    def __init__(self, relayinfo):
        self.relayinfo = relayinfo
        self.fingerprint = relayinfo["fingerprint"]
        self.iptuples = self._parse_or_addresses(relayinfo["or_addresses"])
        self.reachable = list()
    def reachables(self):
        r = list()
        for i in self.reachable:
            r.append("{}:{} {}".format(i[0] if i[0].find(":") == -1 else "[" + i[0] + "]", i[1], self.fingerprint,))
        return r
    def _reachable_str(self):
        return "\n".join(self.reachables())
    def __repr__(self):
        if not self.reachable:
            return str(self.relayinfo)
        return self._reachable_str()
    def __len__(self):
        return len(self.reachable)
    def _parse_or_addresses(self, or_addresses):
        ret = list()
        for address in or_addresses:
            parsed = urllib.parse.urlparse("//" + address)
            ret.append((parsed.hostname, parsed.port))
        return ret
    async def check(self, timeout=10.0):
        for i in self.iptuples:
            s = TCPSocketConnectChecker(i[0], i[1], timeout=timeout)
            sc = await s.connect()
            if sc[0]:
                self.reachable.append(i)
        return bool(self.reachable)

def chunked_list(l, size):
    for i in range(0, len(l), size):
        yield l[i:i+size]

class BridgeScanner:
    def __init__(self, log_callback, update_bridges_callback):
        self.log_callback = log_callback
        self.update_bridges_callback = update_bridges_callback

    async def scan(self):
        NUM_RELAYS = 30
        WORKING_RELAY_NUM_GOAL = 5
        TIMEOUT = 10.0

        self.log_callback("Загрузка информации о ретрансляторах Tor...")
        relay_grabber = TorRelayGrabber(timeout=TIMEOUT)
        relay_grabber.log_callback = self.log_callback
        relays = relay_grabber.grab_parse()

        if not relays:
            self.log_callback("Не удалось загрузить информацию о ретрансляторах!")
            return

        self.log_callback("Загрузка завершена. Начинается сканирование...")
        random.shuffle(relays)

        working_relays = list()
        numtries = (len(relays) + NUM_RELAYS - 1) // NUM_RELAYS
        
        for ntry, chunk in enumerate(chunked_list(relays, NUM_RELAYS)):
            if len(working_relays) >= WORKING_RELAY_NUM_GOAL:
                break

            test_relays = [TorRelay(r) for r in chunk]
            
            self.log_callback(f"Попытка {ntry+1}/{numtries}. Тестирование {len(test_relays)} ретрансляторов...")

            tasks = [asyncio.create_task(relay.check(TIMEOUT)) for relay in test_relays]
            await asyncio.gather(*tasks)
            
            found_this_attempt = []
            for relay in test_relays:
                if relay:
                    working_relays.append(relay)
                    for reachable in relay.reachables():
                        found_this_attempt.append(reachable)
            
            if found_this_attempt:
                self.log_callback(f"Найдено {len(found_this_attempt)} рабочих мостов в этой попытке.")
                self.update_bridges_callback(found_this_attempt)
            else:
                 self.log_callback("Рабочие мосты в этой попытке не найдены.")
