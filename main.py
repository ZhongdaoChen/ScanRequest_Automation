#!/bin/python
import Connector_Nexpose_Postgresql
import Getter_And_Setter
import Confirm_In_DMZ
import os

#  User console, receive IP address


def user_console():
    print("Connecting to the remote database located in secdev-2012r2")
    temp = raw_input("Please input the IP address of the host: ").lstrip().rstrip()
    Getter_And_Setter.set_host_ip(temp)
    conn = Connector_Nexpose_Postgresql.setup_connection_postgresql()
    Connector_Nexpose_Postgresql.retrive_assetsID(conn)
    if Confirm_In_DMZ.comfirm_in_DMZ(conn):
        nexpose_connection = Connector_Nexpose_Postgresql.nexpose_connection()
        choice = input("1: Scan now\n2: schedule future scans\nChoice:  ")
        if Connector_Nexpose_Postgresql.nexpose_scan_request(nexpose_connection, choice) == 'Successful':
            Connector_Nexpose_Postgresql.nexpose_report_request(nexpose_connection)


    else:
        #  if not in our DMZ, process would be exit in Confirm in DMZ function. So pass here
        pass




if __name__ == "__main__":
    while(1):
        os.system('clear')
        user_console()
        repeat = raw_input("Need to schedule another scan? (y/n)")
        if repeat == "y":
            pass
        else:
            exit("Thanks for using")
