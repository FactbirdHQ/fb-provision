# ------------------------------------------------------------------------------
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0 
# ------------------------------------------------------------------------------
# Demonstrates how to call/orchestrate AWS fleet provisioning services
#  with a provided bootstrap certificate (aka - provisioning claim cert).
#   
# Initial version - Raleigh Murch, AWS
# email: murchral@amazon.com
# ------------------------------------------------------------------------------

import paho.mqtt.client as paho
from ecdsa import SigningKey
import time
import datetime
import logging
import json 
import ssl
import os
import asyncio
import glob


def ssl_alpn(cert_filename, key_filename, root_ca, IoT_protocol_name):
    try:
        #debug logInfo opnessl version
        # logInfo("open ssl version:{}".format(ssl.OPENSSL_VERSION))
        ssl_context = ssl.create_default_context()
        ssl_context.set_alpn_protocols([IoT_protocol_name])
        ssl_context.load_verify_locations(cafile=root_ca)
        ssl_context.load_cert_chain(certfile=cert_filename, keyfile=key_filename)
        return ssl_context
    except:
        # logError("ssl contents error")
        raise

class ProvisioningHandler:

    def __init__(self, config, loghandler):
        """Initializes the provisioning handler
        
        Arguments:
            file_path {string} -- path to your configuration file
        """
        #Load configuration settings from config.ini
        # config = Config(file_path)
        self.config_parameters = config.get_section('SETTINGS')
        self.secure_cert_path = self.config_parameters['SECURE_CERT_PATH']
        self.iot_endpoint = self.config_parameters['IOT_ENDPOINT']	
        self.template_name = self.config_parameters['PRODUCTION_TEMPLATE']
        self.rotation_template = self.config_parameters['CERT_ROTATION_TEMPLATE']
        self.claim_cert = self.config_parameters['CLAIM_CERT']
        self.secure_key = self.config_parameters['SECURE_KEY']
        self.root_cert = self.config_parameters['ROOT_CERT']
        self.sign_key = self.config_parameters['SIGN_KEY']
        self.unique_id = self.config_parameters['UUID']

        # ------------------------------------------------------------------------------
        #  -- PROVISIONING HOOKS EXAMPLE --
        # Provisioning Hooks are a powerful feature for fleet provisioning. Most of the
        # heavy lifting is performed within the cloud lambda. However, you can send
        # device attributes to be validated by the lambda. An example is shown in the line
        # below (.hasValidAccount could be checked in the cloud against a database). 
        # Alternatively, a serial number, geo-location, or any attribute could be sent.
        # 
        # -- Note: This attribute is passed up as part of the register_thing method and
        # will be validated in your lambda's event data.
        # ------------------------------------------------------------------------------

        self.primary_MQTTClient = None
        self.test_MQTTClient = None
        self.callback_returned = False
        self.message_payload = {}
        self.isRotation = False

        #Logging
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        self.logger.addHandler(loghandler)

    def logInfo(self, logStr):
        try:
            self.logger.info(str(datetime.datetime.utcnow()) + ": " + logStr)
        except:
            print("cannot log info: " + logStr)
            pass

    def stop(self):
        if self.primary_MQTTClient is not None:
            self.primary_MQTTClient.disconnect()
            
        if self.test_MQTTClient is not None:
            self.test_MQTTClient.disconnect()

    def core_connect(self):
        """ Method used to connect to AWS IoTCore Service. Endpoint collected from config.
        
        """
        if self.isRotation:
            self.logInfo('##### CONNECTING WITH EXISTING CERT #####')
            self.get_current_certs()
        else:
            self.logInfo('##### CONNECTING WITH PROVISIONING CLAIM CERT #####')

        mqttc = paho.Client(self.unique_id)
        mqttc.reconnect_delay_set(min_delay=10) # prevent fast disconnect/connect
        mqttc.on_connect = self.on_connect
        mqttc.on_disconnect = self.on_primary_disconnect
        mqttc.on_message = self.basic_callback
        mqttc.on_subscribe = self.on_subscribe
        mqttc.connected_flag=False

        ssl_context = ssl_alpn(
            "{}/{}".format(self.secure_cert_path, self.claim_cert), 
            "{}/{}".format(self.secure_cert_path, self.secure_key), 
            "{}/{}".format(self.secure_cert_path, self.root_cert), 
            "x-amzn-mqtt-ca"
        )
        mqttc.tls_set_context(context=ssl_context)

        self.primary_MQTTClient = mqttc
        
        self.logInfo("Connecting to {} with client ID '{}'...".format(self.iot_endpoint, self.unique_id))
        self.primary_MQTTClient.connect_async(self.iot_endpoint, 8883)
        self.primary_MQTTClient.loop_start()
        while not self.primary_MQTTClient.connected_flag: #wait in loop
            time.sleep(1)
        self.logInfo("Connected!")

    def on_connect(self, client, userdata, flags, rc):
        if rc==0:
            client.connected_flag=True

        self.logInfo('connection resumed with return code {}, {}'.format(rc, flags))

    def on_subscribe(self, client, userdata, mid, granted_qos):
        self.logInfo('Subscribed successfully')

    def on_primary_disconnect(self, client, userdata, rc=0):
        self.logInfo("Disconnected result code " + str(rc))
        client.connected_flag=False
        self.primary_MQTTClient.loop_stop()

    def on_test_disconnect(self, client, userdata, rc=0):
        self.logInfo("Disconnected result code " + str(rc))
        client.connected_flag=False
        self.test_MQTTClient.loop_stop()

    def get_current_certs(self):
        non_bootstrap_certs = glob.glob('{}/[!boot]*.crt'.format(self.secure_cert_path))
        non_bootstrap_key = glob.glob('{}/[!boot]*.key'.format(self.secure_cert_path))

        #Get the current cert
        if len(non_bootstrap_certs) > 0:
            self.claim_cert = os.path.basename(non_bootstrap_certs[0])

        #Get the current key
        if len(non_bootstrap_key) > 0:
            self.secure_key = os.path.basename(non_bootstrap_key[0])

    def enable_error_monitor(self):
        """ Subscribe to pertinent IoTCore topics that would emit errors
        """

        template_reject_topic = "$aws/provisioning-templates/{}/provision/json/rejected".format(self.template_name)
        certificate_reject_topic = "$aws/certificates/create/json/rejected"
        
        template_accepted_topic = "$aws/provisioning-templates/{}/provision/json/accepted".format(self.template_name)
        certificate_accepted_topic = "$aws/certificates/create/json/accepted"

        subscribe_topics = [(template_reject_topic, 1), (certificate_reject_topic, 1), (template_accepted_topic, 1), (certificate_accepted_topic, 1)]

        self.logInfo("Subscribing to topics '{}'...".format(subscribe_topics))
        self.primary_MQTTClient.subscribe(subscribe_topics)

    def get_official_certs(self, callback, isRotation=False):
        """ Initiates an async loop/call to kick off the provisioning flow.

            Triggers:
               on_message_callback() providing the certificate payload
        """
        if isRotation:
            self.template_name = self.rotation_template
            self.isRotation = True

        return asyncio.run(self.orchestrate_provisioning_flow(callback))

    async def orchestrate_provisioning_flow(self,callback):
        # Connect to core with provision claim creds
        self.core_connect()

        # Monitor topics for errors
        self.enable_error_monitor()

        time.sleep(4)

        # Make a publish call to topic to get official certs
        self.primary_MQTTClient.publish(
            "$aws/certificates/create/json",
            "{}",
            qos=1)

        # Wait the function return until all callbacks have returned
        # Returned denoted when callback flag is set in this class.
        while not self.callback_returned:
            await asyncio.sleep(0)

        return callback(self.message_payload)

    def on_message_callback(self, payload):
        """ Callback Message handler responsible for workflow routing of msg responses from provisioning services.
        
        Arguments:
            payload {bytes} -- The response message payload.
        """
        json_data = json.loads(payload)
        
        # A response has been recieved from the service that contains certificate data. 
        if 'certificateId' in json_data:
            self.logInfo('##### SUCCESS. SAVING KEYS TO DEVICE! #####')
            self.assemble_certificates(json_data)
        
        # A response contains acknowledgement that the provisioning template has been acted upon.
        elif 'deviceConfiguration' in json_data:
            if self.isRotation:
                self.logInfo('##### ACTIVATION COMPLETE #####')
            else:
                self.logInfo('##### CERT ACTIVATED AND THING {} CREATED #####'.format(json_data['thingName']))

            self.validate_certs()
        elif 'service_response' in json_data:
            self.logInfo(json_data)
            self.logInfo('##### SUCCESSFULLY USED PROD CERTIFICATES #####')
        else:
            self.logInfo(json_data)

    def assemble_certificates(self, payload):
        """ Method takes the payload and constructs/saves the certificate and private key. Method uses
        existing AWS IoT Core naming convention.
        
        Arguments:
            payload {string} -- Certifiable certificate/key data.

        Returns:
            ownership_token {string} -- proof of ownership from certificate issuance activity.
        """
        ### Cert ID 
        cert_id = payload['certificateId']
        self.new_key_root = cert_id[0:10]

        self.new_cert_name = '{}-certificate.pem.crt'.format(self.new_key_root)
        ### Create certificate
        f = open('{}/{}'.format(self.secure_cert_path, self.new_cert_name), 'w+')
        f.write(payload['certificatePem'])
        f.close()
        

        ### Create private key
        self.new_key_name = '{}-private.pem.key'.format(self.new_key_root)
        f = open('{}/{}'.format(self.secure_cert_path, self.new_key_name), 'w+')
        f.write(payload['privateKey'])
        f.close()

        ### Extract/return Ownership token
        self.ownership_token = payload['certificateOwnershipToken']
        
        # Register newly aquired cert
        self.register_thing(self.unique_id, self.ownership_token)

    def register_thing(self, serial, token):
        """Calls the fleet provisioning service responsible for acting upon instructions within device templates.
        
        Arguments:
            serial {string} -- unique identifer for the thing. Specified as a property in provisioning template.
            token {string} -- The token response from certificate creation to prove ownership/immediate possession of the certs.
            
        Triggers:
            on_message_callback() - providing acknowledgement that the provisioning template was processed.
        """
        if self.isRotation:
            self.logInfo('##### VALIDATING EXPIRY & ACTIVATING CERT #####')
        else:
            self.logInfo('##### CREATING THING ACTIVATING CERT #####')
        sk_pem = open("{}/{}".format(self.secure_cert_path, self.sign_key), "r").read()
        sk = SigningKey.from_pem(sk_pem)
        signature = sk.sign(serial.encode('utf-8'))
        register_template = {"certificateOwnershipToken": token, "parameters": {"uuid": serial, "signature": signature.hex()}}
        #Register thing / activate certificate
        self.primary_MQTTClient.publish(
            "$aws/provisioning-templates/{}/provision/json".format(self.template_name),
            json.dumps(register_template),
            qos=1)
        time.sleep(2)
        self.logInfo('##### SLEEP DONE #####')
      
    def validate_certs(self):
        """Responsible for (re)connecting to IoTCore with the newly provisioned/activated certificate - (first class citizen cert)
        """
        self.logInfo('##### CONNECTING WITH OFFICIAL CERT #####')
        self.cert_validation_test()
        self.new_cert_pub_sub()
        self.logInfo("##### ACTIVATED AND TESTED CREDENTIALS ({}, {}). #####".format(self.new_key_name, self.new_cert_name))
        self.logInfo("##### FILES SAVED TO {} #####".format(self.secure_cert_path))

    def cert_validation_test(self):
        mqttc = paho.Client(self.unique_id)
        mqttc.reconnect_delay_set(min_delay=10) # prevent fast disconnect/connect
        mqttc.on_connect = self.on_connect
        mqttc.on_disconnect = self.on_test_disconnect
        mqttc.on_message = self.basic_callback
        mqttc.connected_flag=False

        ssl_context = ssl_alpn(
            "{}/{}".format(self.secure_cert_path, self.new_cert_name), 
            "{}/{}".format(self.secure_cert_path, self.new_key_name), 
            "{}/{}".format(self.secure_cert_path, self.root_cert), 
            "x-amzn-mqtt-ca"
        )
        mqttc.tls_set_context(context=ssl_context)

        self.test_MQTTClient = mqttc
        
        self.logInfo("Connecting to {} with client ID '{}'...".format(self.iot_endpoint, self.unique_id))
        self.test_MQTTClient.connect_async(self.iot_endpoint, 8883)
        self.test_MQTTClient.loop_start()
        while not self.test_MQTTClient.connected_flag: #wait in loop
            time.sleep(1)
        self.logInfo("Connected with provisioned certs!")

    def basic_callback(self, client, userdata, message):
        print("Received message from topic '{}': {}".format(message.topic, message.payload))
        self.message_payload = message.payload
        self.on_message_callback(message.payload)
        self.logInfo("Message.topic: {}".format(message.topic))
        if message.topic == "teltonika/status/{}".format(self.unique_id):
            # Finish the run successfully
            self.logInfo("Successfully provisioned")
            self.callback_returned = True
        elif (message.topic == "$aws/provisioning-templates/{}/provision/json/rejected".format(self.template_name) or
            message.topic == "$aws/certificates/create/json/rejected"):
            self.logInfo("Failed provisioning")
            self.callback_returned = True
        else:
            self.logInfo('##### BASIC_CALLBACK FAILED #####')

    def new_cert_pub_sub(self):
        """Method testing a call to the 'teltonika/status/UUID' topic (which was specified in the policy for the new certificate)
        """

        new_cert_topic = "teltonika/status/{}".format(self.unique_id)
        self.logInfo("Subscribing to topic '{}'...".format(new_cert_topic))
        self.test_MQTTClient.subscribe(
            new_cert_topic,
            qos=1)

        self.test_MQTTClient.publish(
            new_cert_topic,
            json.dumps({"service_response": "##### RESPONSE FROM PREVIOUSLY FORBIDDEN TOPIC #####"}),
            qos=1)