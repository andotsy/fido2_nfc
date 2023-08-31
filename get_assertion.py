from fido2 import cbor
from smartcard.CardConnectionObserver import ConsoleCardConnectionObserver
from smartcard.CardMonitoring import CardMonitor, CardObserver
from smartcard.util import toHexString

import requests
import json
import base64
import threading
import hashlib

class SelectAppletObserver(CardObserver):
    def update(self, observable, actions):
        (addedcards, removedcards) = actions
        for card in addedcards:
            card.connection = card.createConnection()
            observer = ConsoleCardConnectionObserver()
            card.connection.addObserver(observer)
            card.connection.connect()

            SELECT = [0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01]
            SELECT_response, sw1, sw2 = card.connection.transmit(SELECT)

            if sw1 == 0x90 and sw2 == 0x00:
                print("FIDO2 applet selected on card:", toHexString(card.atr))

                threading.Thread(target=self.run_fido2_operations, args=(card,)).start()

    def run_fido2_operations(self, card):
        # Connect to the FIDO2 server
        host = "webauthn.io"
        server_url = "https://" + host
        authentication_url = server_url + "/authentication/options"

        # Get session
        session = requests.session()
        session.get(server_url)

        # Fetch the challenge
        # User verification is set to discouraged (which means not performed)
        data = {
            "user_verification": "discouraged"
        }
        headers = {
            "Origin": server_url,
            "Referer": server_url
        }

        response = session.post(authentication_url, data=json.dumps(data), headers=headers)
        challenge_b64 = response.json()["challenge"]

        # Construct the client data JSON
        client_data = {
            "type": "webauthn.get",
            "challenge": challenge_b64,
            "origin": host,
        }

        # Serialize and hash the client data
        client_data_json = json.dumps(client_data, separators=(",", ":"))
        client_data_hash = hashlib.sha256(client_data_json.encode()).digest()

        payload = cbor.encode({
            0x01: host,
            0x02: client_data_hash
        })

        FIDO2_COMMAND_GET_ASSERTION = 0x02

        data_length = len(payload) + 1  # extra byte for FIDO2_COMMAND_GET_ASSERTION
        length_high, length_low = divmod(data_length, 256)  # data_length / 256; data_length % 256

        # [APDU CLA, APDU INS, APDU P1, APDU P2] + [APDU Zero, LenH, LenL] + data
        GET_ASSERTION = [0x80, 0x10, 0x80, 0x00] + [0x00, length_high, length_low] + [FIDO2_COMMAND_GET_ASSERTION] + list(payload)
        response, sw1, sw2 = card.connection.transmit(GET_ASSERTION)

        # If the card responds with 0x9000, it means the operation succeeded
        if sw1 == 0x90 and sw2 == 0x00:
            print("Authenticated successfully")
            print("Response:", toHexString(response))
        else:
            print("Authentication failed")

if __name__ == '__main__':
    cardmonitor = CardMonitor()
    selectobserver = SelectAppletObserver()
    cardmonitor.addObserver(selectobserver)

    try:
        while True:
            pass
    except:
        cardmonitor.deleteObserver(selectobserver)
        raise
