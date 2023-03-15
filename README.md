## MQTT based fleet provisioning for Blackbird AWS IoT things

This repository contains a slightly enhanced implementation on top of the [AWS FleetProvisioning Service](https://docs.aws.amazon.com/iot/latest/developerguide/provision-wo-cert.html) for provisioning AWS IoT Core devices without certificates. An multi-cloud router layer has been put on top of the existing provisioning flow, that will route the device to the appropriate Blackbird cloud, where the device has been claimed by a customer. Furthermore we require devices to provide a pre-registered `claim` certificate, that authenticates the provisioning flow to exchange said `claim` certificate for unique device certificates in aforementioned appropriate Blackbird cloud.

This implementation is provided by Blackbird in 3 programming languages in this repo:

- Rust (`#![no_std]`, `heapless` & `async`)
- Java (Greengrass trusted plugin)
- Python

![provisioning](docs/provision.png)
