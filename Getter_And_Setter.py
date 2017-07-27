#!/bin/python


def set_host_ip(host_ip):
    global HOST_IP
    HOST_IP = host_ip


def get_host_ip():
    return HOST_IP


def set_host_assetID(host_assetID):
    global ASSET_ID
    ASSET_ID = host_assetID


def get_host_assetID():
    return ASSET_ID


def set_host_name(host_name):
    global HOST_NAME
    HOST_NAME = host_name


def get_host_name():
    return HOST_NAME


def set_host_siteID(host_siteID):
    global SITE_ID
    SITE_ID = host_siteID


def get_host_siteID():
    return SITE_ID
