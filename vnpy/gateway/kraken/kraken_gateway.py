"""
Gateway for Kraken Crypto Exchange.
"""

import urllib
import hashlib
import hmac
import time
from typing import Dict
from copy import copy
from datetime import datetime, timedelta
from enum import Enum
from threading import Lock
import base64

from vnpy.api.rest import RestClient, Request
from vnpy.api.websocket import WebsocketClient
from vnpy.trader.constant import (
    Direction,
    Exchange,
    Product,
    Status,
    OrderType,
    Interval
)
from vnpy.trader.gateway import BaseGateway, LocalOrderManager
from vnpy.trader.object import (
    TickData,
    OrderData,
    TradeData,
    AccountData,
    ContractData,
    BarData,
    OrderRequest,
    CancelRequest,
    SubscribeRequest,
    HistoryRequest
)
from vnpy.trader.event import EVENT_TIMER
from vnpy.event import Event


REST_HOST = "https://api.kraken.com"
WEBSOCKET_PUBLIC_HOST = "wss://ws.kraken.com"
WEBSOCKET_PRIVATE_HOST = "wss://ws-auth.kraken.com"

STATUS_KRAKEN2VT = {
    "pending": Status.SUBMITTING,
    "open": Status.NOTTRADED,
    "partial": Status.PARTTRADED,
    "closed": Status.ALLTRADED,
    "canceled": Status.CANCELLED,
    "rejected": Status.REJECTED
}

ORDERTYPE_VT2KRAKEN = {
    OrderType.LIMIT: "limit",
    OrderType.MARKET: "market"
}
ORDERTYPE_KRAKEN2VT = {v: k for k, v in ORDERTYPE_VT2KRAKEN.items()}

DIRECTION_VT2KRAKEN = {
    Direction.LONG: "buy",
    Direction.SHORT: "sell"
}
DIRECTION_KRAKEN2VT = {v: k for k, v in DIRECTION_VT2KRAKEN.items()}

INTERVAL_VT2KRAKEN = {
    Interval.MINUTE: 1,
    Interval.HOUR: 60,
    Interval.DAILY: 1440,
}

TIMEDELTA_MAP = {
    Interval.MINUTE: timedelta(minutes=1),
    Interval.HOUR: timedelta(hours=1),
    Interval.DAILY: timedelta(days=1),
}


KRAKEN_MININUM_VOLUMN = {
    "ALGO": 50,
    "XREP": 0.3,
    "BAT": 50,
    "XXBT": 0.002,
    "BCH": 0.000002,
    "ADA": 1,
    "LINK": 10,
    "ATOM": 1,
    "DAI": 10,
    "DASH": 0.03,
    "XDG": 3000,
    "EOS": 3,
    "XETH": 0.02,
    "XETC": 0.3,
    "GNO": 0.02,
    "ICX": 50,
    "LSK": 10,
    "XLTC": 0.1,
    "XXMR": 0.1,
    "NANO": 10,
    "OMG": 10,
    "PAXG": 0.01,
    "QTUM": 0.1,
    "XRP": 30,
    "SC": 5000,
    "XXLM": 30,
    "USDT": 5,
    "XTZ": 1,
    "TRX": 500,
    "USDC": 5,
    "XMLN": 0.1,
    "WAVES": 10,
    "XZEC": 0.03,
    "ZEUR": 10,
    "ZUSD": 10,
    "ZGBP": 10,

}

class Security(Enum):
    PUBLIC = 0
    PRIVATE = 1


symbol2ws_map = {}
ws2symbol_map = {}

class KrakenGateway(BaseGateway):

    default_setting = {
        "key": "",
        "secret": "",
        "session_number": 3,
        "proxy_host": "",
        "proxy_port": 0,
    }

    exchanges = [Exchange.KRAKEN]

    def __init__(self, event_engine):
        """Constructor"""
        super().__init__(event_engine, "KRAKEN")

        self.order_manager = LocalOrderManager(self)

        self.trade_ws_api = KrakenTradeWebsocketApi(self)
        self.market_ws_api = KrakenMarketWebsocketApi(self)
        self.rest_api = KrakenRestApi(self)

    def connect(self, setting: dict):
        """"""
        key = setting["key"]
        secret = setting["secret"]
        session_number = setting["session_number"]
        proxy_host = setting["proxy_host"]
        proxy_port = setting["proxy_port"]

        self.rest_api.connect(key, secret, session_number,
                              proxy_host, proxy_port)
        self.market_ws_api.connect(proxy_host, proxy_port)

    def subscribe(self, req: SubscribeRequest):
        """"""
        self.market_ws_api.subscribe(req)

    def send_order(self, req: OrderRequest):
        """"""
        return self.rest_api.send_order(req)

    def cancel_order(self, req: CancelRequest):
        """"""
        self.rest_api.cancel_order(req)

    def query_account(self):
        """"""
        pass

    def query_position(self):
        """"""
        pass

    def query_history(self, req: HistoryRequest):
        """"""
        return self.rest_api.query_history(req)

    def close(self):
        """"""
        self.rest_api.stop()
        self.trade_ws_api.stop()
        self.market_ws_api.stop()


class KrakenRestApi(RestClient):
    """
    KRAKEN REST API
    """

    def __init__(self, gateway: KrakenGateway):
        """"""
        super().__init__()

        self.gateway = gateway
        self.gateway_name = gateway.gateway_name

        self.trade_ws_api = self.gateway.trade_ws_api

        self.key = ""
        self.secret = ""

        self.recv_window = 5000
        self.time_offset = 0

        self.order_count = 1_000_000
        self.order_count_lock = Lock()
        self.connect_time = 0

    def _sign(self, data, urlpath):
        """ Sign request data according to Kraken's scheme.

        :param data: API request parameters
        :type data: dict
        :param urlpath: API URL path sans host
        :type urlpath: str
        :returns: signature digest
        """
        postdata = urllib.parse.urlencode(data)

        # Unicode-objects must be encoded before hashing
        encoded = (str(data['nonce']) + postdata).encode()
        message = urlpath.encode() + hashlib.sha256(encoded).digest()

        signature = hmac.new(base64.b64decode(self.secret),
                             message, hashlib.sha512)
        sigdigest = base64.b64encode(signature.digest())

        return sigdigest.decode()

    def sign(self, request):
        """
        Generate KRAKENs signature.
        """
        security = request.data["security"]
        del request.data['security']

        if security == Security.PUBLIC:
            request.data = None
            return request

        # private

        nonce = int(time.time() * 1000)
        request.data['nonce'] = nonce
        urlpath = request.path


        # Add headers
        request.headers = {
            'API-Key': self.key,
            'API-Sign': self._sign(request.data, urlpath)
        }

        return request

    def connect(
        self,
        key: str,
        secret: str,
        session_number: int,
        proxy_host: str,
        proxy_port: int
    ):
        """
        Initialize connection to REST server.
        """
        self.key = key
        self.secret = secret.encode()
        self.proxy_port = proxy_port
        self.proxy_host = proxy_host

        self.connect_time = (
            int(datetime.now().strftime("%y%m%d%H%M%S")) * self.order_count
        )

        self.init(REST_HOST, proxy_host, proxy_port)
        self.start(session_number)

        self.gateway.write_log("REST API启动成功")

        self.query_time()
        self.query_account()
        self.query_order()
        self.query_contract()
        self.start_private_websocket()

    def query_time(self):
        """"""
        data = {"security": Security.PUBLIC}

        return self.add_request(
            method="GET",
            path="/0/public/Time",
            callback=self.on_query_time,
            data=data
        )

    def query_account(self):
        """"""
        data = {"security": Security.PRIVATE}

        self.add_request(
            method="POST",
            path="/0/private/Balance",
            callback=self.on_query_account,
            data=data
        )

    def query_order(self):
        """"""
        data = {"security": Security.PRIVATE}

        self.add_request(
            method="POST",
            path="/0/private/OpenOrders",
            callback=self.on_query_order,
            data=data
        )

    def query_contract(self):
        """"""
        data = {"security": Security.PUBLIC}

        self.add_request(
            method="GET",
            path="/0/public/AssetPairs",
            callback=self.on_query_contract,
            data=data
        )

    def send_order(self, req: OrderRequest):
        """"""
        local_orderid = self.order_manager.new_local_orderid()
        order = req.create_order_data(
            local_orderid,
            self.gateway_name
        )
        order.time = datetime.now().strftime("%H:%M:%S")

        data = {
            "security": Security.PRIVATE,

            "pair": req.symbol,
            "type": DIRECTION_VT2KRAKEN[req.direction],
            "ordertype": ORDERTYPE_VT2KRAKEN[req.type],
            "price": str(req.price),
            "volume": str(req.volume),
            "userref": orderid,
            "validate": false
        }

        self.add_request(
            method="POST",
            path="/0/private/AddOrder",
            callback=self.on_send_order,
            data=data,
            extra=order,
            on_error=self.on_send_order_error,
            on_failed=self.on_send_order_failed
        )

        self.order_manager.on_order(order)
        return order.vt_orderid

    def cancel_order(self, req: CancelRequest):
        """"""
        sys_orderid = self.order_manager.get_sys_orderid(req.orderid)

        data = {
            "security": Security.SIGNED,

            "txid": sys_orderid
        }
        self.add_request(
            method="POST",
            path="/0/private/CancelOrder",
            callback=self.on_cancel_order,
            extra=req
        )

    def start_private_websocket(self):
        """"""
        data = {"security": Security.PRIVATE}

        self.add_request(
            method="POST",
            path="/0/private/GetWebSocketsToken",
            callback=self.on_start_private_websocket,
            data=data
        )

    def on_query_time(self, data, request):
        """"""
        local_time = int(time.time() * 1000)
        server_time = int(data['result']["unixtime"]) * 1000
        self.time_offset = local_time - server_time

    def on_query_account(self, data, request):
        """"""
        if self.check_error(data, "查询账户"):
            return
        for accountid, balance in data["result"].items():
            account = AccountData(
                accountid=accountid,
                balance=float(balance),
                frozen=0.0,
                gateway_name=self.gateway_name
            )

            if account.balance:
                self.gateway.on_account(account)

        self.gateway.write_log("账户资金查询成功")

    def on_query_order(self, data, request):
        """"""
        if self.check_error(data, "查询委托"):
            return

        for id, d in data['result']['open'].items():
            dt = datetime.fromtimestamp(float(d["opentm"]))
            time = dt.strftime("%Y-%m-%d %H:%M:%S")
            status = d["status"]
            if d["status"] == "open" and float(d["vol_exec"]) > 0:
                status = "partial"

            order = OrderData(
                orderid=d["refid"],
                symbol=d["descr"]["pair"],
                exchange=Exchange.KRAKEN,
                price=float(d["descr"]["price"]),
                volume=float(d["vol"]),
                type=ORDERTYPE_KRAKEN2VT[d["descr"]["ordertype"]],
                direction=DIRECTION_KRAKEN2VT[d["descr"]["type"]],
                traded=float(d["vol_exec"]),
                status=STATUS_KRAKEN2VT.get(status),
                time=time,
                gateway_name=self.gateway_name,
            )
            self.gateway.on_order(order)

        self.gateway.write_log("委托信息查询成功")

    def on_query_contract(self, data, request):
        """"""
        if self.check_error(data, "查询合约"):
            return

        for pair_name, d in data["result"].items():
            base_currency = d["base"]
            quote_currency = d["quote"]
            name = f"{base_currency.upper()}/{quote_currency.upper()}"

            pricetick = 10 ** -int(d["pair_decimals"])
            min_volume = KRAKEN_MININUM_VOLUMN.get(base_currency, 1)

            contract = ContractData(
                symbol=pair_name,
                exchange=Exchange.KRAKEN,
                name=name,
                pricetick=pricetick,
                size=1,
                min_volume=min_volume,
                product=Product.SPOT,
                history_data=True,
                gateway_name=self.gateway_name,
            )
            if d.get('wsname'):
                self.gateway.on_contract(contract)
                symbol2ws_map[contract.symbol] = d["wsname"]
                ws2symbol_map[d["wsname"]] = contract.symbol

        self.gateway.write_log("合约信息查询成功")

    def on_send_order(self, data, request):
        """"""
        order = request.extra

        if self.check_error(data, "委托"):
            order.status = Status.REJECTED
            self.order_manager.on_order(order)
            return

        sys_orderid = data["result"]["txid"]
        self.order_manager.update_orderid_map(order.orderid, sys_orderid)

    def on_send_order_failed(self, status_code: str, request: Request):
        """
        Callback when sending order failed on server.
        """
        order = request.extra
        order.status = Status.REJECTED
        self.gateway.on_order(order)

        msg = f"委托失败，状态码：{status_code}，信息：{request.response.text}"
        self.gateway.write_log(msg)

    def on_send_order_error(
        self, exception_type: type, exception_value: Exception, tb, request: Request
    ):
        """
        Callback when sending order caused exception.
        """
        order = request.extra
        order.status = Status.REJECTED
        self.gateway.on_order(order)

        # Record exception if not ConnectionError
        if not issubclass(exception_type, ConnectionError):
            self.on_error(exception_type, exception_value, tb, request)

    def on_cancel_order(self, data, request):
        """"""
        cancel_request = request.extra
        local_orderid = cancel_request.orderid
        order = self.order_manager.get_order_with_local_orderid(local_orderid)

        if self.check_error(data, "撤单"):
            order.status = Status.REJECTED
        else:
            order.status = Status.CANCELLED
            self.gateway.write_log(f"委托撤单成功：{order.orderid}")

        self.order_manager.on_order(order)

    def on_error(
        self, exception_type: type, exception_value: Exception, tb, request: Request
    ):
        """
        Callback to handler request exception.
        """
        msg = f"触发异常，状态码：{exception_type}，信息：{exception_value}"
        self.gateway.write_log(msg)

        sys.stderr.write(
            self.exception_detail(exception_type, exception_value, tb, request)
        )

    def on_start_private_websocket(self, data, request):
        """"""
        token = data['result']['token']

        self.trade_ws_api.connect(WEBSOCKET_PRIVATE_HOST, token, self.proxy_host, self.proxy_port)

    def query_history(self, req: HistoryRequest):
        """"""
        # Create query params
        """"""
        history = []
        start_time = int(datetime.timestamp(req.start))


        # Create query params
        params = {
            "pair": req.symbol,
            "interval": INTERVAL_VT2KRAKEN[req.interval]
        }

        # Get response from server
        resp = self.request(
            "GET",
            "/0/public/OHLC",
            params=params
        )

        # Break if request failed with other status code
        if resp.status_code // 100 != 2:
            msg = f"获取历史数据失败，状态码：{resp.status_code}，信息：{resp.text}"
            self.gateway.write_log(msg)
            return history
        else:
            data = resp.json()
            if not data:
                msg = f"获取历史数据为空，开始时间：{start_time}"
                self.gateway.write_log(msg)
                return history


            for l in data["result"][req.symbol]:
                dt = datetime.fromtimestamp(l[0])    # convert to second

                bar = BarData(
                    symbol=req.symbol,
                    exchange=req.exchange,
                    datetime=dt,
                    interval=req.interval,
                    volume=float(l[6]),
                    open_price=float(l[1]),
                    high_price=float(l[2]),
                    low_price=float(l[3]),
                    close_price=float(l[4]),
                    gateway_name=self.gateway_name
                )
                history.append(bar)

            begin = history[0].datetime
            end = history[-1].datetime
            msg = f"获取历史数据成功，{req.symbol} - {req.interval.value}，{begin} - {end}"
            self.gateway.write_log(msg)

        return history

    def check_error(self, data: dict, func: str = ""):
        """"""
        if data["error"]:
            error_msg = data["error"][0]
            self.gateway.write_log(f"{func}请求出错，信息：{error_msg}")
            return True

        return False

class KrakenTradeWebsocketApi(WebsocketClient):
    def __init__(self, gateway):
        """"""
        super().__init__()

        self.gateway = gateway
        self.gateway_name = gateway.gateway_name
        self.order_manager = gateway.order_manager
        self.order_manager.push_data_callback = self.on_data

        self.old_trades = None

    def connect(self, url, token, proxy_host, proxy_port):
        """"""
        self.token = token
        self.init(url, proxy_host, proxy_port)
        self.start()

    def on_connected(self):
        """"""
        self.gateway.write_log("交易Websocket API连接成功")
        sub_open_orders = {
            "event": "subscribe",
            "subscription": {
                "name": "openOrders",
                "token": self.token
            }
        }
        sub_trade = {
            "event": "subscribe",
            "subscription": {
                "name": "ownTrades",
                "token": self.token
            }
        }
        self.send_packet(sub_open_orders)
        self.send_packet(sub_trade)

    def on_packet(self, packet: dict):  # type: (dict)->None
        """"""
        if isinstance(packet, dict):
            self.on_event(packet)
        elif isinstance(packet, list):
            self.on_data(packet)

    def on_event(self, packet):
        pass

    def on_data(self, packet):
        if packet[1] == 'ownTrades':
            self.on_trade(packet)
        elif packet[1] == 'openOrders':
            self.on_order(packet)

    def on_order(self, packet):
        """"""
        orders = packet[0]
        for o1 in orders:
            for sys_orderid, o in o1.items():
                order = self.order_manager.get_order_with_sys_orderid(sys_orderid)
                if not order:
                    self.order_manager.add_push_data(sys_orderid, data)
                    continue

                if o.get("descr"):
                    # full order
                    dt = datetime.fromtimestamp(float(o["opentm"]))
                    time = dt.strftime("%Y-%m-%d %H:%M:%S")

                    order.traded = o["vol_exec"]
                    order.time = time

                order.status = STATUS_KRAKEN2VT.get(o["status"])
                self.order_manager.on_order(order)


    def on_trade(self, packet):
        """"""
        t1 = packet[0]
        if self.old_trades is None:
            self.old_trades = set()
            for t in t1:
                for tradeid, o in t.items():
                    self.old_trades.add(tradeid)
            return


        for t in t1:
            for tradeid, o in t.items():
                if tradeid in self.old_trades:
                    continue

                self.old_trades.add(tradeid)
                # Push trade event
                trade_volume = float(o["vol"])
                trade_dt = datetime.fromtimestamp(float(o["time"]))
                trade_time = trade_dt.strftime("%Y-%m-%d %H:%M:%S")

                sys_orderid = o["ordertxid"]
                local_orderid = self.order_manager.get_local_orderid(sys_orderid)

                trade = TradeData(
                    symbol=ws2symbol_map[o["pair"]],
                    exchange=Exchange.KRAKEN,
                    orderid=local_orderid,
                    tradeid=tradeid,
                    direction=DIRECTION_KRAKEN2VT[o["type"]],
                    price=float(o["price"]),
                    volume=trade_volume,
                    time=trade_time,
                    gateway_name=self.gateway_name,
                )
                self.gateway.on_trade(trade)

class KrakenDepthLevel:
    def __init__(self, price, vol):
        self.price = price
        self.vol = vol

class KrakenDepth:
    def __init__(self):
        self.bids = None
        self.asks = None

    def init(self, bids, asks):
        self.bids = self._price_map(bids)
        self.asks = self._price_map(asks)

    def _price_map(self, l):
        ret = []
        for n in l:
            ret.append(KrakenDepthLevel(n[0], n[1]))
        return ret

    def update(self, a, b):
        if a:
            for n in self._price_map(a):
                self.asks = [x for x in self.asks if x.price != n.price]
                if float(n.vol) != 0:
                    self.asks.append(n)
            self.asks = sorted(self.asks, key=lambda x: x.price, reverse=True)
            self.asks = self.asks[:9]
        if b:
            for n in self._price_map(b):
                self.bids = [x for x in self.bids if x.price != n.price]
                if float(n.vol) != 0:
                    self.bids.append(n)
            self.bids = sorted(self.bids, key=lambda x: x.price, reverse=False)
            self.bids = self.bids[:9]

    def to_tick(self, tick):
        for n in range(5):
            l = self.bids[n]
            tick.__setattr__("bid_price_" + str(n + 1), float(l.price))
            tick.__setattr__("bid_volume_" + str(n + 1), float(l.vol))
        for n in range(5):
            l = self.asks[n]
            tick.__setattr__("ask_price_" + str(n + 1), float(l.price))
            tick.__setattr__("ask_volume_" + str(n + 1), float(l.vol))



class KrakenMarketWebsocketApi(WebsocketClient):
    def __init__(self, gateway):
        """"""
        super().__init__()

        self.gateway = gateway
        self.gateway_name = gateway.gateway_name

        self.ticks: Dict[str, TickData] = {}
        self.depth: Dict[str, KrakenDepth] = {}

    def connect(self, proxy_host: str, proxy_port: int):
        """"""
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port

    def on_connected(self):
        """"""
        self.gateway.write_log("行情Websocket API连接刷新")
        pair = []
        for symbol in self.ticks.keys():
            pair.append(symbol2ws_map[symbol])
        sub_ticker = {
            "event": "subscribe",
            "pair": pair,
            "subscription": {
                "name": "ticker"
            }
        }
        sub_depth = {
            "event": "subscribe",
            "pair": pair,
            "subscription": {
                "name": "book",
                "depth": 10
            }
        }
        self.send_packet(sub_ticker)
        self.send_packet(sub_depth)

    def subscribe(self, req: SubscribeRequest):
        """"""
        if req.symbol not in symbol2ws_map:
            self.gateway.write_log(f"找不到该合约代码{req.symbol}")
            return

        # Create tick buf data
        tick = TickData(
            symbol=req.symbol,
            name=symbol2ws_map.get(req.symbol),
            exchange=Exchange.KRAKEN,
            datetime=datetime.now(),
            gateway_name=self.gateway_name,
        )
        self.ticks[req.symbol] = tick

        self.depth[req.symbol] = KrakenDepth()

        # Close previous connection
        if self._active:
            self.stop()
            self.join()

        self.init(WEBSOCKET_PUBLIC_HOST, self.proxy_host, self.proxy_port)
        self.start()

    def on_packet(self, packet):
        """"""
        if isinstance(packet, dict):
            self.on_event(packet)
        elif isinstance(packet, list):
            self.on_data(packet)

    def on_event(self, packet):
        pass

    def on_data(self, packet):
        channel = packet[-2]
        symbol = ws2symbol_map[packet[-1]]
        data = packet[1]

        tick = self.ticks[symbol]

        if channel == "ticker":
            tick.volume = float(data['v'][1])
            tick.open_price = float(data['o'][1])
            tick.high_price = float(data['h'][1])
            tick.low_price = float(data['l'][1])
            tick.last_price = float(data['c'][0])
            tick.datetime = datetime.now()
        else:
            d = self.depth[symbol]
            bids = data.get("bs")
            asks = data.get("as")
            if bids is not None and asks is not None:
                d.init(bids, asks)

            a = data.get('a')
            b = data.get('b')
            d.update(a, b)

            d.to_tick(tick)

        if tick.last_price:
            self.gateway.on_tick(copy(tick))