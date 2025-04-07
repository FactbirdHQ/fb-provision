/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

// package com.aws.greengrass;

// import com.aws.greengrass.testcommons.testutilities.ggextension;
// import org.junit.jupiter.api.beforeeach;
// import org.junit.jupiter.api.test;
// import org.junit.jupiter.api.extension.extendwith;
// import org.mockito.argumentcaptor;
// import org.mockito.mock;
// import org.mockito.junit.jupiter.mockitoextension;
// import software.amazon.awssdk.crt.mqtt.qualityofservice;
// import software.amazon.awssdk.iot.iotidentity.iotidentityclient;
// import software.amazon.awssdk.iot.iotidentity.model.createkeysandcertificateresponse;
// import software.amazon.awssdk.iot.iotidentity.model.createcertificatefromcsrresponse;
// import software.amazon.awssdk.iot.iotidentity.model.registerthingrequest;
// import software.amazon.awssdk.iot.iotidentity.model.registerthingresponse;

// import java.util.hashmap;
// import java.util.concurrent.completablefuture;
// import java.util.concurrent.future;
// import java.util.function.consumer;

// import static org.junit.jupiter.api.assertions.assertequals;
// import static org.mockito.argumentmatchers.any;
// import static org.mockito.argumentmatchers.eq;
// import static org.mockito.mockito.verify;
// import static org.mockito.mockito.when;

// @extendwith({mockitoextension.class, ggextension.class})
// public class iotidentityhelpertest {

//     private static final string mock_certificate_ownership_token = "mock_certificate_ownership_token";
//     private static final string mock_certificate_id = "mock_certificate_id";
//     private static final string mock_certificate_pem = "mock_certificate_pem";
//     private static final string mock_private_key = "mock_private_key";
//     private static final string mock_template_name = "mock_template_name";
//     private static final string mock_thing_name = "mock_thing_name";
//     private static final string mock_csr_certificate = "mock_csr_certificate";

//     private iotidentityhelper iotidentityhelper;

//     @mock
//     private iotidentityclient iotidentityclient;

//     @beforeeach
//     public void setup () {
//         iotidentityhelper = new iotidentityhelper(iotidentityclient);

//     }

//     @test
//     public void given_create_keys_method_invoked_when_api_successful_then_expected_response_retuned() throws exception {
//         when(iotidentityclient.subscribetocreatekeysandcertificateaccepted(any(), any(), any()))
//                 .thenreturn(completablefuture.completedfuture(0));
//         when(iotidentityclient.subscribetocreatekeysandcertificaterejected(any(), any(), any()))
//                 .thenreturn(completablefuture.completedfuture(0));
//         when(iotidentityclient.publishcreatekeysandcertificate(any(), eq(qualityofservice.at_least_once)))
//                 .thenreturn(completablefuture.completedfuture(0));
//         future<createkeysandcertificateresponse> response =
//                 iotidentityhelper.createkeysandcertificate();

//         argumentcaptor<consumer> consumerargumentcaptor = argumentcaptor.forclass(consumer.class);
//         verify(iotidentityclient).subscribetocreatekeysandcertificateaccepted(any(),
//                 eq(qualityofservice.at_least_once), consumerargumentcaptor.capture());
//         verify(iotidentityclient).subscribetocreatekeysandcertificaterejected(any(),
//                 eq(qualityofservice.at_least_once), any());
//         verify(iotidentityclient).publishcreatekeysandcertificate(any(),
//                 eq(qualityofservice.at_least_once));
//         consumer acceptedconsumer = consumerargumentcaptor.getvalue();
//         acceptedconsumer.accept(createmockcreatekeysandcertificateresponse());
//         createkeysandcertificateresponse returnedresponse = response.get();
//         assertequals(mock_private_key, returnedresponse.privatekey);
//         assertequals(mock_certificate_id, returnedresponse.certificateid);
//         assertequals(mock_certificate_ownership_token, returnedresponse.certificateownershiptoken);
//         assertequals(mock_certificate_pem, returnedresponse.certificatepem);
//     }

//     @test
//     public void given_create_certificate_from_csr_method_invoked_when_api_successful_then_expected_response_retuned() throws exception {
//         when(iotidentityclient.subscribetocreatecertificatefromcsraccepted(any(), any(), any()))
//                 .thenreturn(completablefuture.completedfuture(0));
//         when(iotidentityclient.subscribetocreatecertificatefromcsrrejected(any(), any(), any()))
//                 .thenreturn(completablefuture.completedfuture(0));
//         when(iotidentityclient.publishcreatecertificatefromcsr(any(), eq(qualityofservice.at_least_once)))
//                 .thenreturn(completablefuture.completedfuture(0));
//         future<createcertificatefromcsrresponse> response =
//                 iotidentityhelper.createcertificatefromcsr(mock_csr_certificate);

//         argumentcaptor<consumer> consumerargumentcaptor = argumentcaptor.forclass(consumer.class);
//         verify(iotidentityclient).subscribetocreatecertificatefromcsraccepted(any(),
//                 eq(qualityofservice.at_least_once), consumerargumentcaptor.capture());
//         verify(iotidentityclient).subscribetocreatecertificatefromcsrrejected(any(),
//                 eq(qualityofservice.at_least_once), any());
//         verify(iotidentityclient).publishcreatecertificatefromcsr(any(),
//                 eq(qualityofservice.at_least_once));
//         consumer acceptedconsumer = consumerargumentcaptor.getvalue();
//         acceptedconsumer.accept(createmockcreatecertificatefromcsrresponse());
//         createcertificatefromcsrresponse returnedresponse = response.get();
//         assertequals(mock_certificate_id, returnedresponse.certificateid);
//         assertequals(mock_certificate_ownership_token, returnedresponse.certificateownershiptoken);
//         assertequals(mock_certificate_pem, returnedresponse.certificatepem);
//     }

//     @test
//     public void given_register_thing_method_invoked_when_api_successful_then_expected_response_retuned() throws exception {
//         when(iotidentityclient.subscribetoregisterthingaccepted(any(), any(), any(), any()))
//                 .thenreturn(completablefuture.completedfuture(0));
//         when(iotidentityclient.subscribetoregisterthingrejected(any(), any(), any(), any()))
//                 .thenreturn(completablefuture.completedfuture(0));

//         hashmap<string, string> templateparams = new hashmap<>();
//         templateparams.put("serialnumber", "11");
//         future<registerthingresponse> response =
//                 iotidentityhelper.registerthing(mock_certificate_ownership_token, mock_template_name, templateparams);

//         argumentcaptor<consumer> consumerargumentcaptor = argumentcaptor.forclass(consumer.class);
//         verify(iotidentityclient).subscribetoregisterthingaccepted(any(),
//                 eq(qualityofservice.at_least_once), consumerargumentcaptor.capture(), any());
//         verify(iotidentityclient).subscribetoregisterthingrejected(any(),
//                 eq(qualityofservice.at_least_once), any(), any());
//         argumentcaptor<registerthingrequest> registerrequestcaptor =
//                 argumentcaptor.forclass(registerthingrequest.class);
//         verify(iotidentityclient).publishregisterthing(registerrequestcaptor.capture(),
//                 eq(qualityofservice.at_least_once));
//         registerthingrequest registerthingrequest = registerrequestcaptor.getvalue();
//         assertequals(templateparams, registerthingrequest.parameters);
//         assertequals(mock_template_name, registerthingrequest.templatename);
//         assertequals(mock_certificate_ownership_token, registerthingrequest.certificateownershiptoken);

//         consumer acceptedconsumer = consumerargumentcaptor.getvalue();
//         acceptedconsumer.accept(createmockregisterthingresponse());
//         registerthingresponse returnedresponse = response.get();
//         assertequals(mock_thing_name, returnedresponse.thingname);
//     }

//     private registerthingresponse createmockregisterthingresponse() {
//         registerthingresponse registerthingresponse = new registerthingresponse();
//         registerthingresponse.thingname = mock_thing_name;
//         return registerthingresponse;
//     }

//     private createkeysandcertificateresponse createmockcreatekeysandcertificateresponse() {
//         createkeysandcertificateresponse mock = new createkeysandcertificateresponse();
//         mock.certificateid = mock_certificate_id;
//         mock.certificateownershiptoken = mock_certificate_ownership_token;
//         mock.certificatePem = MOCK_CERTIFICATE_PEM;
//         mock.privateKey = MOCK_PRIVATE_KEY;
//         return mock;
//     }

//     private CreateCertificateFromCsrResponse createMockCreateCertificateFromCsrResponse() {
//         CreateCertificateFromCsrResponse mock = new CreateCertificateFromCsrResponse();
//         mock.certificateId = MOCK_CERTIFICATE_ID;
//         mock.certificateOwnershipToken = MOCK_CERTIFICATE_OWNERSHIP_TOKEN;
//         mock.certificatePem = MOCK_CERTIFICATE_PEM;
//         return mock;
//     }

// }
