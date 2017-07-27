import re
import xml.etree.ElementTree as ET
import pyfpdf
import sys
import getopt

vul_counter = 1
kernel_security_count = 0
app_update = []
pattern_ip = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')  # Extract IP from file name. I know it's ugly. bite me?
separator = "\n----------------------------------------------------------------------------" \
            "----------------------------------------------------------------------------" \
            "--------------------------------------------------\n"

#  system_kernel_vulnerabilities = ["FreeBSD", "Kernel"]  # these words indicate it's a kernel vulnerabilities,
# we nee to enumerate this list
#  See line 93


def help_info():
    print("********************************************************************")
    print("Nexpose Report Simplifier\n"
          "Version: 1.0  Author: Zhongdao Chen\n\n"
          "Usage: simplify_scan_report..py -s [least severity] -i [XML filename]\n"
          "severity range (1-10), above 3 is critical and severe\n"
          "For Example: python simplify_scan_report.py -s 3 -i xml_69.173.66.124.xml\n\n"
          "XML filename can also be file path\n"
          "The simplified report name is Simplified_Report.pdf")
    print("********************************************************************")


def get_kernel_security_count():
    global kernel_security_count
    return kernel_security_count


def set_kernel_security_count():
    global kernel_security_count
    kernel_security_count += 1


def get_vul_counter():
    global vul_counter
    return vul_counter


def set_vul_counter():
    global vul_counter
    vul_counter += 1


def set_severity(severity):
    global SEVERITY
    SEVERITY = severity


def get_severity():
    global SEVERITY
    return SEVERITY


def set_xml_filename(ifile):
    global xml_filename
    xml_filename = ifile


def get_xml_filename():
    global xml_filename
    return xml_filename


def get_vulnerability_nodes():
    tests = []
    fp = open("./output.txt", 'w+')

    try:
        tree = ET.ElementTree(file=get_xml_filename())

    except:
        print("XML file not found\n")
        exit(0)

    root = tree.getroot()
    for child_of_root in root:
        if child_of_root.tag == "VulnerabilityDefinitions":
            vul_defi_root = child_of_root
            for child_of_vul_defi in vul_defi_root:
                if str(child_of_vul_defi.tag) == "vulnerability" \
                        and int(child_of_vul_defi.get("severity")) >= int(get_severity()):
                    vulnerability_node = child_of_vul_defi
                    if "FreeBSD" in vulnerability_node.get("title") or "Kernel" in vulnerability_node.get("title") \
                            or "Red Hat" in vulnerability_node.get("title") or "Cent OS" in \
                            vulnerability_node.get("title"):
                        # NEED TO REWRITE THIS PART TO TRAVERSE WORD LIST, OR JUST KEEP THE CODE UGLY
                        set_kernel_security_count()
                        continue

                    elif "update" in str(vulnerability_node.get("title")):
                        app_update.append(vulnerability_node.get("title"))
                        continue

                    else:
                        fp.write(str(get_vul_counter()) + ":" + str(vulnerability_node.get("title")) + " -- Severity: "
                                 + str(vulnerability_node.get("severity")) + "\n")
                        set_vul_counter()
                        # Need to provide more information from the <test> tag
                        for test_node in child_node_test.iter():
                            if str(test_node.tag) == "test" and str(test_node.get("id")) == \
                                    str(vulnerability_node.get("id")):
                                for test_node_child in test_node.iter():
                                    if str(test_node_child.text) != "None":
                                        tests.append(' '.join(str(test_node_child.text).split()))
                                    if str(test_node_child.get("LinkURL")) != "None":
                                        tests.append(' '.join(str(test_node_child.get("LinkURL")).split()))

                    for current_node in child_of_vul_defi.iter():
                        if current_node.tag == "tags" or current_node.tag == "tag":  # Those tags are not necessary
                            continue

                        elif current_node.tag == "references" or current_node.tag == "reference":
                            continue

                        elif current_node.tag == "vulnerability":
                            continue

                        elif current_node.tag == "UnorderedList":
                            continue

                        elif str(current_node.tag) == "URLLink":
                            if str(current_node.text) != "":
                                temp = str(current_node.get("LinkURL"))

                            else:
                                temp = str(current_node.get("LinkURL"))

                        else:
                            temp = str(current_node.tag) + str(current_node.attrib) + str(current_node.text)

                        temp = ' '.join(temp.split())
                        temp = temp.replace("Paragraph{}", "").replace("ContainerBlockElement{}", "")
                        temp = temp.replace("description{}", "Description:")
                        temp = temp.replace("solution{}", "Solution:")
                        temp = temp.replace("references{}", "References:")
                        temp = temp.replace("UnorderedList{}", "")
                        temp = temp.replace("ListItem{}", "")
                        temp = temp.replace("Paragraph", "")
                        temp = temp.replace("{'preformat': 'true'}", "")

                        if temp == "":
                            continue
                        else:
                            fp.write(temp + "\n")
                    #  output for <test> if valid
                    fp.write("Details:\n")
                    for i in tests:
                        if len(i) != 0:
                            fp.write(i + "\n")
                    tests = []
                else:
                    # if the severity is not >= what you set, skip
                    continue
            if len(app_update) != 0:
                fp.write("\nAlso, the following applications or protocols are outdated.v"
                         "Most of them should be updated automatically after reboot." + "\n")
                for app in app_update:
                    fp.write(app + "\n")
            fp.close()
        elif child_of_root.tag == "nodes":
            child_node_test = child_of_root


def format_output():
    num = 0
    length_of_line = 0
    index = 0
    asset_ip = str(pattern_ip.findall(get_xml_filename())).strip("[]'")
    fp_result = open("./final_report.txt", 'w+')
    fp_result.write("Scan report for " + str(asset_ip) + "\n")
    if get_kernel_security_count() >= 1:
        fp_result.write(("***********IMPORTANT***********\n " +
                         "There are " + str(get_kernel_security_count()) + " system kernel vulnerabilities! "
                         "Please Reboot to get system patched ASAP." + str(separator)) + "\n")
    with open('./output.txt') as fp1:
        for line in fp1:
            if len(line) > 100 and " " not in line:
                # This part temporary, I'm gonna write a loop instead after fixing other bugs
                # Or not :)
                if 110 <= len(line) < 220:
                    lst = list(line)
                    lst.insert(110, '-\n')
                    line = ''.join(lst)
                elif 220 <= len(line) < 330:
                    lst = list(line)
                    lst.insert(110, '-\n')
                    lst.insert(220, '-\n')
                    line = ''.join(lst)
                elif 330 <= len(line) <= 440:
                    lst = list(line)
                    lst.insert(110, '-\n')
                    lst.insert(220, '-\n')
                    lst.insert(330, '-\n')
                    line = ''.join(lst)
                elif 440 <= len(line) <= 550:
                    lst = list(line)
                    lst.insert(110, '-\n')
                    lst.insert(220, '-\n')
                    lst.insert(330, '-\n')
                    lst.insert(440, '-\n')
                    line = ''.join(lst)
                elif len(line) > 550:
                    lst = list(line)
                    lst.insert(110, '-\n')
                    lst.insert(220, '-\n')
                    lst.insert(330, '-\n')
                    lst.insert(440, '-\n')
                    lst.insert(550, '-\n')
                    line = ''.join(lst)
            else:
                lst = line.split(" ")
                for word in lst:
                    if "\n" in word:
                        index = 0
                        length_of_line = 0
                        continue
                    else:
                        if length_of_line <= 120:
                            length_of_line += len(str(word))
                            index += 1
                        else:
                            lst.insert(index, '\n')
                            length_of_line = 0
                line = ' '.join(lst)
            num += 1
            if "Severity" in line and num != 1:
                line = separator + line
            fp_result.write(line)
    fp1.close()
    fp_result.close()


def export_to_pdf():
    pdf = pyfpdf.fpdf.FPDF(format="Letter")
    pdf.add_page()
    pdf.set_font("Arial", size=12)

#  Put different colors
    with open('./final_report.txt') as fp1:
        for line in fp1:
            if "Scan report for" in line:
                pdf.set_font('Times', size=18)
                pdf.set_text_color(0, 0, 0)
                pdf.cell(0, 8, line, border=0, ln=1, align="C")
            elif "Description" in line or "Solution" in line:
                pdf.set_font('Times', size=10)
                pdf.set_text_color(0, 0, 255)
                pdf.cell(0, 8, line, border=0, ln=1)

            elif "Severity" in line or "IMPORTANT" in line:
                pdf.set_font('Times', size=10)
                pdf.set_text_color(255, 0, 0)
                pdf.cell(0, 8, line, border=0, ln=1)

            elif "applications or protocols" in line:
                pdf.set_font('Times', size=10)
                pdf.set_text_color(255, 0, 0)
                pdf.cell(0, 8, line, border=0, ln=1)

            elif "Details" in line:
                pdf.set_font('Times', size=10)
                pdf.set_text_color(0, 0, 255)
                pdf.cell(0, 8, line, border=0, ln=1)

            else:
                pdf.set_font("Arial", size=8)
                pdf.set_text_color(0, 0, 0)
                pdf.cell(0, 8, line, border=0, ln=1)
    pdf.output("Simplified_Report.pdf")


def main(argv):
    if len(argv) != 4:
        print("INPUT ERROR\n")
        help_info()
        exit(0)
    else:
        try:
            opts, args = getopt.getopt(argv, "hs:i:", ["SEVERITY=", "xml_filename="])
        except getopt.GetoptError:
            help_info()
            sys.exit(2)
        for opt, arg in opts:
            if opt == "-h":
                help_info()
                sys.exit()
            elif opt in ("-s", "--severity"):
                set_severity(arg)
            elif opt in ("-i", "--ifile"):
                set_xml_filename(arg)

        get_vulnerability_nodes()
        format_output()
        export_to_pdf()
        print("Done :))))\n")

if __name__ == "__main__":
    main(sys.argv[1:])

