
from flask import Flask, request
from dsp3.models.manager import Manager

app = Flask(__name__)


@app.route('/', methods=['GET', 'POST'])
def lambda_handler(event=None, context=None):
    print("hello")

    if event != None:

        if 'detail' in event:
            type = event['detail']['type'] if 'type' in event['detail'] else ""
            print("EVENT=", event)

            if type != "":
                if 'Recon:IAMUser/MaliciousIPCaller.Custom' in type:
                    #Not secure. should be passed and environment variables to function
                    dsm = Manager(username='username', password='password', tenant='ACME Corp')
                    print("************* Initiating connection to Deep Security As A Service")
                    ip = event['detail']['service']['action']['awsApiCallAction']['remoteIpDetails']['ipAddressV4']
                    ip_list = dsm.get_ip_list_by_name('Guard Duty Block List')
                    ip_list.items = ip_list.items + ('\n%s' % ip)
                    dsm.ip_list_save(ip_list)
                    print("************* Adding %s to IP List - Guard Duty Block List" % ip)
                    dsm.end_session()
                    print("************* Closing connection to Deep Security As A Service")

    return 'gd-test'