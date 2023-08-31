from fido2 import cbor
from smartcard.CardConnectionObserver import ConsoleCardConnectionObserver
from smartcard.CardMonitoring import CardMonitor, CardObserver
from smartcard.util import toHexString

import threading

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

                threading.Thread(target=self.reset_fido2, args=(card,)).start()

    def reset_fido2(self, card):
        CARD_RESET = [0x80, 0x10, 0x80, 0x00, 0x01, 0x07]
        response, sw1, sw2 = card.connection.transmit(CARD_RESET)

        if sw1 == 0x90 and sw2 == 0x00:
            print("FIDO2 applet was successfully reset.")
        else:
            print("Card reset command failed. Status Words:", hex(sw1), hex(sw2))

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
