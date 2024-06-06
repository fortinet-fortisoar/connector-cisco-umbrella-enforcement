"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

import requests, json, datetime
import inspect
from connectors.core.connector import get_logger, ConnectorError
from .cisco_api_auth import *

logger = get_logger('cisco_umbrella_enforcement')

error_msgs = {400: "Bad request. Server unable to process request.",
              401: "Unauthorized. Make sure that the API key is valid.",
              403: "Unauthorized. Make sure that API Key provided for connector configuration is valid.",
              404: "Object not found. The requested object could not be found.",
              500: "Internal server error."
              }


def get_destination_lists(config, params, connector_info):
    destination_lists_url = '{0}/policies/v2/destinationlists'.format(config.get('url'))
    return make_api_call(config, destination_lists_url, method='GET', params={}, connector_info=connector_info)


def _get_input_list(input_list):
    if isinstance(input_list, (list, tuple)):
        return list(input_list)
    elif isinstance(input_list, str):
        return [item.strip() for item in input_list.split(',')]
    else:
        logger.error("Invalid input CSV: {0}".format(input_list))
        raise ConnectorError("Invalid input CSV: {0}".format(input_list))


def add_destination(config, params, connector_info):
    destination_add_url = '{0}/policies/v2/destinationlists/{1}/destinations'.format(config.get('url'),
                                                                                     params.get('listId'))
    destinations = _get_input_list(params.get('destinations'))
    comment = params.get('comment') if params.get('comment') else 'Suspicious destination'
    payload = []
    for destination in destinations:
        payload.append({"destination": destination, "comment": comment})
    return make_api_call(config, destination_add_url, method='POST', body=json.dumps(payload),
                         connector_info=connector_info)


def list_destinations(config, params, connector_info):
    destination_lists_url = '{0}/policies/v2/destinationlists/{1}/destinations'.format(config.get('url'),
                                                                                       params.get('listId'))
    req_params = {}
    if params.get("page") and params.get("page") != "":
        req_params["page"] = params.get("page")
    if params.get("limit") and params.get("limit") != "":
        req_params["limit"] = params.get("limit")
    return make_api_call(config, destination_lists_url, method='GET', params=req_params, connector_info=connector_info)


def delete_destinations_from_list(config, params, connector_info):
    destination_delete_url = '{0}/policies/v2/destinationlists/{1}/destinations/remove'.format(config.get('url'),
                                                                                               params.get('listId'))
    payload = []
    dest_ids = _get_input_list(params.get('id'))
    for dest in dest_ids:
        payload.append(int(dest))
    return make_api_call(config, destination_delete_url, method='DELETE', body=json.dumps(payload), connector_info=connector_info)


def _error_message_log(message):
    func_name = inspect.stack()[1][3]
    err_msg = func_name + ": " + message
    logger.error(err_msg)
    raise ConnectorError(message)


def get_token(config, connector_info):
    try:
        go = CiscoAuth(config)
        token = go.validate_token(config, connector_info)
        return token
    except Exception as err:
        logger.error(err)
        raise ConnectorError(err)


def make_api_call(config, url, method='GET', params=None, body=None, connector_info=None):
    try:
        token = get_token(config, connector_info)
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + token
        }
        response = requests.request(method=method, url=url, params=params, headers=headers, data=body,
                                    verify=config.get('verify_ssl'))

        if response.status_code == 204:
            return True
        if response.status_code in error_msgs.keys():
            message = "HTTP {0}:{1}".format(response.status_code, error_msgs.get(response.status_code, "Unknown Error"))
            logger.error(message)
            raise ConnectorError(message)

        else:
            try:
                json_response = response.json()
                if json_response:
                    return json_response
                else:
                    _error_message_log(message='No Response.')

            except ValueError:
                return _error_message_log(message='JSON response could not be decoded.')
    except requests.exceptions.SSLError:
        return _error_message_log(message='An SSL error occurred.')
    except requests.exceptions.ConnectTimeout:
        return _error_message_log(message='Connection Timeout.')
    except requests.exceptions.ConnectionError:
        return _error_message_log(message='A connection error occurred.')
    except requests.exceptions.RequestException:
        return _error_message_log(message='There was an error while handling the request.')
    except Exception as err:
        return _error_message_log(message=format(str(err)))


def _check_health(config, connector_info):
    try:
        result = check(config, connector_info)
        if result:
            return True
    except Exception as e:
        logger.error("{0}".format(str(e)))
        raise ConnectorError("{0}".format(str(e)))


operations = {
    'add_destination': add_destination,
    'get_destination_lists': get_destination_lists,
    'list_destinations': list_destinations,
    'delete_destinations_from_list': delete_destinations_from_list
}
