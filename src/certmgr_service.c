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
#include <pulse/pulseaudio.h>
#include <pulse/glib-mainloop.h>

#include "certmgr_service.h"
#include "luna_service_utils.h"
#include "utils.h"

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

static bool list_all_cb(LSHandle *handle, LSMessage *message, void *user_data)
{
	luna_service_message_reply_error_not_implemented(handle, message);

	return true;
}

static bool install_cb(LSHandle *handle, LSMessage *message, void *user_data)
{
	luna_service_message_reply_error_not_implemented(handle, message);

	return true;
}

static bool remove_cb(LSHandle *handle, LSMessage *message, void *user_data)
{
	luna_service_message_reply_error_not_implemented(handle, message);

	return true;
}

struct certmgr_service* certmgr_service_create()
{
	struct certmgr_service *service;
	LSError error;

	service = g_try_new0(struct certmgr_service, 1);
	if (!service)
		return NULL;

	LSErrorInit(&error);

	if (!LSRegisterPubPriv("org.webosports.certmgr", &service->handle, false, &error)) {
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
