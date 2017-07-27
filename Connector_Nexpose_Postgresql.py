import psycopg2
import Getter_And_Setter
import pnexpose
import time
import getpass


def setup_connection_postgresql():
    # If a formal database is implemented, please uncomment these lines and delete the conn line
    '''
    database_username = raw_input("Please input database connection username: ")
    database_password = getpass.getpass()
    conn = psycopg2.connect(host=“INPUT DB ADDRESS HERE”, port='5432', database='postgres', user=database_username, password=database_password)
    '''

    conn = psycopg2.connect(host="10.200.0.41", port="5432", database="postgres", user="postgres", password=“testtest”)
    if conn:
        print("Connection Established.")
        return conn
    else:
        print("Connection failed!\n")


def retrive_assetsID(conn):
    cur = conn.cursor()
    ip = Getter_And_Setter.get_host_ip()
    sql = 'SELECT asset_id, host_name from "public"."dim_asset" WHERE ip_address =' + "'" + ip + "'"
    print("Committing sql query: " + sql + "\n")
    cur.execute(sql)
    rows = cur.fetchall()

    if len(rows) > 1:
        print("Warning! Duplicated AssetID found in database! The host has two different asset_id. Please check the "
              "database table 'dim-asset'\n ")
        exit("Duplication found")

    elif len(rows) == 0:
        print("Asset Not Found in database!\n")
        exit("Asset Not Found")

    else:
        temp_assetID = str(rows).split(',')[0][2:-1]
        temp_hostname = str(rows).split(',')[1][2:-3]
        Getter_And_Setter.set_host_assetID(temp_assetID)
        Getter_And_Setter.set_host_name(temp_hostname)
        print("Information Received, Please confirm if it is the host you want\n"
              "HostName: {0}, IP: {1}, AssetID: {2}").format(temp_hostname, ip, temp_assetID)
        confirm = raw_input("y/n: ")
        yes = ['y', 'yes', 'Y', 'Yes', 'YES']
        if confirm in yes:
            pass
        else:
            print("Please check the information in database table 'dim_asset'\n")
            exit("Database info not correct")


def nexpose_connection():
    serveraddr = 'rapid7nexpose.broadinstitute.org'
    port = 3780
    while 1:
        username = raw_input("Please input your Nexpose Username: ")
        password = getpass.getpass()
       #   password = raw_input("Password: ")
        print("Trying to connect to Nexpose engine...\n")
        try:
            nexposeClient = pnexpose.Connection(serveraddr, port, username, password)
            return nexposeClient

        except:
            print("Username or password incorrect, please retry")




def nexpose_report_request(nexposeClient):
    query = ""
    site_ids = []
    scan_ids = []
    device_ids = [int(Getter_And_Setter.get_host_assetID())]
    response = nexposeClient.adhoc_report(query, site_ids, scan_ids, device_ids)
    report_name = Getter_And_Setter.get_host_ip() + ".xml"
    f = open('./' + report_name, 'w+')
    print >>f, response
    print("\nReport generated successfully. Please check the "+ report_name)


def nexpose_scan_request(nexposeClient, choice):
    site_ids = str(Getter_And_Setter.get_host_siteID())
    device_ids = str(Getter_And_Setter.get_host_assetID())
    scan_id = nexposeClient.SiteDevicesScan(site_ids, device_ids, choice)

    if choice == 1:
        print("The scan status will be update every 30 seconds\n")
        while(1):
            result = nexposeClient.scan_status(int(scan_id))
            print("Process: " + result)
            if "finished" in result:
                return 'Successful'
            time.sleep(30)

    else:
        print("Schedule set!\n")
