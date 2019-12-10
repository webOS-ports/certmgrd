/* @@@LICENSE
*
* Copyright (c) 2013 Simon Busch <morphis@gravedo.de>
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* LICENSE@@@ */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <glib.h>
#include <pbnjson.h>
#include <luna-service2/lunaservice.h>

#include <cert_mgr.h>
#include <cert_mgr_prv.h>
#include <cert_cfg.h>
#include <cert_pkcs.h>
#include <cert_x509.h>
#include <cert_utils.h>
#include <cert_db.h>

#include "certmgr_service.h"
#include "luna_service_utils.h"
#include "utils.h"

#define DEFAULT_CONF_PATH	"/etc/ssl/openssl.cnf"

extern GMainLoop *event_loop;

struct certmgr_service {
	LSHandle *handle;
};

static bool list_all_cb(LSHandle *handle, LSMessage *message, void *user_data);
static bool install_cb(LSHandle *handle, LSMessage *message, void *user_data);
static bool remove_cb(LSHandle *handle, LSMessage *message, void *user_data);

static LSMethod certmgr_service_methods[]  = {
	{ "listAll", list_all_cb },
	{ "install", install_cb },
	{ "remove", remove_cb },
	{ NULL, NULL }
};

const char* status_value_to_str(char status)
{
	switch (status) {
	case 'c':
		return "trusted-server-ca";
	case 'x':
		return "all";
	case 'C':
		return "valid-ca";
	case 'E':
		return "expired";
	case 'p':
		return "valid-peer";
	case 'P':
		return "trusted-peer";
	case 'R':
		return "revoked";
	case 'S':
		return "suspended";
	case 'T':
		return "trusted-cient-ca";
	case 'V':
		return "valid-cert";
	case 'u':
		return "user-certificate";
	case 'w':
		return "warning";
	case 'X':
		return "unknown";
	default:
		break;
	}

	return "undefined";
}

static bool list_all_cb(LSHandle *handle, LSMessage *message, void *user_data)
{
	int count = 0, ret, n, num;
	char path[MAX_CERT_PATH];
	char serial[128];
	char property_start[64] = { 0 };
	char property_expiration[64] = { 0 };
	char property_issuer[64] = { 0 };
	char property_issuer_organization[64] = { 0 };
	char property_subject_organization[64] = { 0 };
	char property_subject[64] = { 0 };
	char property_subject_surname[64] = { 0 };
	char property_subject_organization_unit[64] = { 0 };
	char property_issuer_organization_unit[64] = { 0 };
	X509 *cert = 0;
	jvalue_ref reply_obj;
	jvalue_ref certs_obj;
	jvalue_ref cert_obj;

	ret = CertGetDatabaseInfo(CERT_DATABASE_SIZE, &count);
	if (ret != 0) {
		luna_service_message_reply_error_internal(handle, message);
		goto cleanup;
	}

	reply_obj = jobject_create();

	certs_obj = jarray_create(0);

	for (n = 0; n < count; n++) {
		ret = CertGetDatabaseStrValue(n, CERT_DATABASE_ITEM_SERIAL, serial, 128);
		num = atoi(serial);

		ret = makePathToCert(num, path, MAX_CERT_PATH);
		if (ret != 0)
			continue;

		ret = CertPemToX509(path, &cert);
		if (ret != 0)
			continue;

		cert_obj = jobject_create();

		jobject_put(cert_obj, J_CSTR_TO_JVAL("serial"), jnumber_create_i32(num));

		CertX509ReadTimeProperty(cert, CERTX509_START_DATE, property_start, 64);
		jobject_put(cert_obj, J_CSTR_TO_JVAL("start"), jstring_create(property_start));

		CertX509ReadTimeProperty(cert, CERTX509_EXPIRATION_DATE, property_expiration, 64);
		jobject_put(cert_obj, J_CSTR_TO_JVAL("expiration"), jstring_create(property_expiration));

		CertX509ReadStrProperty(cert, CERTX509_ISSUER_COMMON_NAME, property_issuer, 64);
		jobject_put(cert_obj, J_CSTR_TO_JVAL("issuer"), jstring_create(property_issuer));

		CertX509ReadStrProperty(cert, CERTX509_SUBJECT_ORGANIZATION_NAME, property_subject_organization, 64);
		jobject_put(cert_obj, J_CSTR_TO_JVAL("subjectOrganization"), jstring_create(property_subject_organization));

		CertX509ReadStrProperty(cert, CERTX509_ISSUER_ORGANIZATION_NAME, property_issuer_organization, 64);
		jobject_put(cert_obj, J_CSTR_TO_JVAL("issuerOrganization"), jstring_create(property_issuer_organization));

		CertX509ReadStrProperty(cert, CERTX509_SUBJECT_COMMON_NAME, property_subject, 64);
		jobject_put(cert_obj, J_CSTR_TO_JVAL("subject"), jstring_create(property_subject));

		CertX509ReadStrProperty(cert, CERTX509_SUBJECT_SURNAME, property_subject_surname, 64);
		jobject_put(cert_obj, J_CSTR_TO_JVAL("subjectSurname"), jstring_create(property_subject_surname));

		CertX509ReadStrProperty(cert, CERTX509_SUBJECT_ORGANIZATION_UNIT_NAME, property_subject_organization_unit, 64);
		jobject_put(cert_obj, J_CSTR_TO_JVAL("subjectOrganizationUnit"), jstring_create(property_subject_organization_unit));

		CertX509ReadStrProperty(cert, CERTX509_ISSUER_ORGANIZATION_UNIT_NAME, property_issuer_organization_unit, 64);
		jobject_put(cert_obj, J_CSTR_TO_JVAL("issuerOrganizationUnit"), jstring_create(property_issuer_organization_unit));

		jarray_append(certs_obj, cert_obj);
	}

	jobject_put(reply_obj, J_CSTR_TO_JVAL("certificates"), certs_obj);
	jobject_put(reply_obj, J_CSTR_TO_JVAL("returnValue"), jboolean_create(true));

	if (!luna_service_message_validate_and_send(handle, message, reply_obj))
		goto cleanup;

cleanup:
	if (!jis_null(reply_obj))
		j_release(&reply_obj);

	return true;
}

static bool install_cb(LSHandle *handle, LSMessage *message, void *user_data)
{
	const char *payload;
	jvalue_ref parsed_obj;
	char *path, *passphrase;
	int ret, serial;

	payload = LSMessageGetPayload(message);
	parsed_obj = luna_service_message_parse_and_validate(payload);
	if (jis_null(parsed_obj)) {
		luna_service_message_reply_error_bad_json(handle, message);
		goto cleanup;
	}

	path = luna_service_message_get_string(parsed_obj, "path", NULL);
	if (!path) {
		luna_service_message_reply_custom_error(handle, message, "No path provided");
		goto cleanup;
	}

	passphrase = luna_service_message_get_string(parsed_obj, "passphrase", NULL);

	if (!g_file_test(path, G_FILE_TEST_IS_REGULAR)) {
		luna_service_message_reply_custom_error(handle, message, "Invalid path provided");
		goto cleanup;
	}

	ret = CertInstallKeyPackage(path, NULL, passphrase, &serial);
	if (ret != 0) {
		luna_service_message_reply_custom_error(handle, message, "Failed to add certificate (wrong passphrase?)");
		goto cleanup;
	}

	ret = CertAddAuthorizedCert(serial);
	if (ret != 0) {
		luna_service_message_reply_custom_error(handle, message, "Could not add imported certificate as authorized");
		goto cleanup;
	}

	luna_service_message_reply_success(handle, message);

cleanup:
	if (!jis_null(parsed_obj))
		j_release(&parsed_obj);

	return true;
}

static bool remove_cb(LSHandle *handle, LSMessage *message, void *user_data)
{
	const char *payload;
	jvalue_ref parsed_obj;
	int ret, serial;

	payload = LSMessageGetPayload(message);
	parsed_obj = luna_service_message_parse_and_validate(payload);
	if (jis_null(parsed_obj)) {
		luna_service_message_reply_error_bad_json(handle, message);
		goto cleanup;
	}

	serial = luna_service_message_get_int(parsed_obj, "serial", 0);
	g_message("serial %d", serial);
	if (!serial) {
		luna_service_message_reply_custom_error(handle, message, "Invalid serial supplied");
		goto cleanup;
	}

	ret = CertRemoveCertificate(serial);
	if (ret != 0) {
		luna_service_message_reply_custom_error(handle, message, "Could not remove certificate");
		goto cleanup;
	}

	luna_service_message_reply_success(handle, message);

cleanup:
	if (!jis_null(parsed_obj))
		j_release(&parsed_obj);

	return true;
}

struct certmgr_service* certmgr_service_create()
{
	struct certmgr_service *service;
	LSError error;
	int ret;

	service = g_try_new0(struct certmgr_service, 1);
	if (!service)
		return NULL;

	LSErrorInit(&error);

	if (!LSRegister("org.webosports.service.certmgr", &service->handle, &error)) {
		g_warning("Failed to register the luna service: %s", error.message);
		LSErrorFree(&error);
		goto error;
	}

	if (!LSRegisterCategory(service->handle, "/", certmgr_service_methods,
			NULL, NULL, &error)) {
		g_warning("Could not register service category: %s", error.message);
		LSErrorFree(&error);
		goto error;
	}

	if (!LSCategorySetData(service->handle, "/", service, &error)) {
		g_warning("Could not set daa for service category: %s", error.message);
		LSErrorFree(&error);
		goto error;
	}

	if (!LSGmainAttach(service->handle, event_loop, &error)) {
		g_warning("Could not attach service handle to mainloop: %s", error.message);
		LSErrorFree(&error);
		goto error;
	}

	ret = CertInitCertMgr(DEFAULT_CONF_PATH);
	if (ret != 0) {
		g_warning("Failed to initialize certificate manager (%d)", ret);
		goto error;
	}

	return service;

error:
	if (service->handle != NULL) {
		LSUnregister(service->handle, &error);
		LSErrorFree(&error);
	}

	g_free(service);

	return NULL;
}

void certmgr_service_free(struct certmgr_service *service)
{
	LSError error;

	LSErrorInit(&error);

	if (service->handle != NULL && LSUnregister(service->handle, &error) < 0) {
		g_warning("Could not unregister service: %s", error.message);
		LSErrorFree(&error);
	}

	g_free(service);
}

// vim:ts=4:sw=4:noexpandtab
