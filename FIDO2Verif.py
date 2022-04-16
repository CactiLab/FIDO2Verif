# coding=gbk
import itertools
import os
import sys
import threading
import shutil
import getopt
from threading import Timer
from subprocess import Popen, PIPE

"""
The Auto Script to generate .pv files for each case.
These cases consist of: leaked field(s), compromised channels, queries.
Call ProVerif to verify all the .pv files of different cases
"""


class Setting:
    """
    General Setting Class
    RootPath is the directory where the .pv and .pvl files exist
    set_type_row     is the line to insert the type definition
    reg_fields_row   is the line to insert compromised fields for registration
    auth_fields_row  is the line to insert compromised fields for authentication
    reg_entities_row  is the line to insert compromised entities for registration
    auth_entities_row is the line to insert compromised entities for authentication
    the testing cases are divided into
    reg:  (c / s) client-side / server-side storage
    auth: (c / s) * (empty / simple / generic)
    """
    RootPath = os.getcwd() + "/"
    set_type_row = 8
    reg_fields_row = 17
    auth_fields_row = 23
    reg_entities_noctap_row = 22
    reg_entities_ctap_row_1 = 31
    reg_entities_ctap_row = 38
    auth_entities_noctap_row = 28
    auth_entities_ctap_row_1 = 37
    auth_entities_ctap_row = 44

    if os.path.exists(RootPath + "LOG/"):
        shutil.rmtree(RootPath + "LOG/")
    if os.path.exists(RootPath + "TEMP/"):
        shutil.rmtree(RootPath + "TEMP/")
    if os.path.exists(RootPath + "Result/"):
        shutil.rmtree(RootPath + "Result/")

    if not os.path.exists(RootPath + "LOG/"):
        os.makedirs(RootPath + "LOG/")
    if not os.path.exists(RootPath + "TEMP/"):
        os.makedirs(RootPath + "TEMP/")
    if not os.path.exists(RootPath + "Result/"):
        os.makedirs(RootPath + "Result/")
    RegPath = RootPath + "Reg.pv"
    AuthPath = RootPath + "Auth.pv"
    LogPath1 = RootPath + "LOG\\reg_c.log"
    LogPath2 = RootPath + "LOG\\reg_s.log"
    LogPath3 = RootPath + "LOG\\auth_c_emp.log"
    LogPath4 = RootPath + "LOG\\auth_c_sim.log"
    LogPath5 = RootPath + "LOG\\auth_c_gen.log"
    LogPath6 = RootPath + "LOG\\auth_s_emp.log"
    LogPath7 = RootPath + "LOG\\auth_s_sim.log"
    LogPath8 = RootPath + "LOG\\auth_s_gen.log"
    LibPath = RootPath + "FIDO2.pvl"
    ResultPath = RootPath + "Result/"  # the path for analysis results
    ScriptPath = RootPath + "TEMP/"    # the path for current .pv files
    analyze_flag = "full"  # "full" to analyze all scenarios, "simple" to analyze without fields leakage.

    # check the validity of all the paths
    @classmethod
    def initiate(cls):
        if not os.path.exists(cls.LibPath):
            print("FIDO2.lib does not exist")
            sys.exit(1)
        if not os.path.exists(cls.RegPath):
            print("Reg.pv does not exist")
            sys.exit(1)
        if not os.path.exists(cls.AuthPath):
            print("Auth.pv does not exist")
            sys.exit(1)


class Type:  # indicate the type of this test case
    def __init__(self, name, write):
        self.name = name    # name of this type: reg_client, the registration process of client-side authenticator
        self.write = write  # the code to set this type "let au_type = client"

class CTAPType:
    def __init__(self, name, write):
        self.name = name    # name of this type: reg_client, the registration process of client-side authenticator
        self.write = write


class Query:  # indicate the query statement
    def __init__(self, name, write):
        self.name = name    # name of this query: S-cntr, the secrecy of counter
        self.write = write  # the query sentence in .pv file


class Fields:  # indicate a specific combination of compromised fields
    def __init__(self, fields):
        self.nums = len(fields)  # the number of leaked fields
        self.write = ""          # the code of leaked fields in .pv file
        self.name = "fields-" + str(self.nums)  # the name "fields-0/1/2/3/4/5......" in output
        for item in fields:
            self.write += item  # source code are stored in the item
        self.fields = fields


class Entities:
    def __init__(self, entities, row_numbers):
        self.nums = len(entities)
        self.write = ""
        if self.nums == 0:
            self.name = "mali-" + str(self.nums)
        else:
            self.name = "mali-" + str(self.nums) + ",,"
            for i in row_numbers:
                self.name += "," + str(i)
        for item in entities:
            self.write += item
        self.entities = entities  # the list of 
        self.row_numbers = row_numbers  # the list of indexes of this combination


class AllTypes:
    """
    a parent class for all authenticator types
    give different values to au_type and tr_type in sub-cases
    run the different branches in the code
    """

    def __init__(self):
        self.all_types = []

    def size(self):
        return len(self.all_types)

    def get(self, i):
        return self.all_types[i]


class AllCTAPType(AllTypes):
    def __init__(self):
        AllTypes.__init__(self)
        self.all_types.append(CTAPType("noCTAP", "let ctap_type = noCTAP in\n"))
        self.all_types.append(CTAPType("setPIN", "let ctap_type = setPIN in\n"))
        self.all_types.append(CTAPType("chgPIN", "let ctap_type = chgPIN in\n"))
        self.all_types.append(CTAPType("getToken", "let ctap_type = getToken in\n"))       


class RegClientTypes(AllTypes):  # The cases using client-side storage authenticators in registration
    def __init__(self):
        AllTypes.__init__(self)
        self.all_types.append(Type("reg_client", "let au_type = client in\n"))


class RegServerTypes(AllTypes):  # The cases using server-side storage authenticators in registration
    def __init__(self):
        AllTypes.__init__(self)
        self.all_types.append(Type("reg_server", "let au_type = server in\n"))


class AuthClientEmpTypes(AllTypes): # The cases using client-side storage authenticators in authentication
    def __init__(self):
        AllTypes.__init__(self)
        self.all_types.append(Type("auth_client_em", "let au_type = client in\nlet tr_type = empty in\n"))


class AuthClientSimTypes(AllTypes):  # The cases using client-side storage authenticators in Simple Transaction Authorization
    def __init__(self):
        AllTypes.__init__(self)
        self.all_types.append(Type("auth_client_sim", "let au_type = client in\nlet tr_type = simple in\n"))


class AuthClientGenTypes(AllTypes):  # The cases using client-side storage authenticators in Generic Transaction Authorization
    def __init__(self):
        AllTypes.__init__(self)
        self.all_types.append(Type("auth_client_gen", "let au_type = client in\nlet tr_type = generic in\n"))


class AuthServerEmpTypes(AllTypes):  # The cases using server-side storage authenticators in authentication
    def __init__(self):
        AllTypes.__init__(self)
        self.all_types.append(Type("auth_server_em", "let au_type = server in\nlet tr_type = empty in\n"))


class AuthServerSimTypes(AllTypes):  # The cases using server-side storage authenticators in Simple Transaction Authorization
    def __init__(self):
        AllTypes.__init__(self)
        self.all_types.append(Type("auth_server_sim", "let au_type = server in\nlet tr_type = simple in\n"))


class AuthServerGenTypes(AllTypes):  # The cases using server-side storage authenticators in Generic Transaction Authorization
    def __init__(self):
        AllTypes.__init__(self)
        self.all_types.append(Type("auth_server_gen", "let au_type = server in\nlet tr_type = generic in\n"))


class AllQueries:
    """
    A parent class for all queries
    This class indicates the queries commonly analyzed for all types of authenticator and all cases(reg/auth).
    The queries of a specific subclass can be added on top of these.
    You can customize other queries as you wish.
    """

    def __init__(self):
        self.all_queries = []
        self.all_queries.append(Query("S-pintok", "query secret PinToken.\n"))
        self.all_queries.append(Query("S-cntr", "query secret testcntr.\n"))
        self.all_queries.append(Query("S-creid", "query secret testcreid.\n"))
        self.all_queries.append(Query("S-skau", "query secret skau.\n"))

    def size(self):
        return len(self.all_queries)

    def get(self, i):
        return self.all_queries[i]


class RegClientQueries(AllQueries):
    """
    As for using client-side storage authenticators in registration
    0. wrapping key wk are not used
    1. attestation private key should be protected
    2. the authentication property A5: RP obtain injective agreement on (UserHandle,RpID,AAGUID,CreID) with FC
    3. the authentication property A6: RP obtain injective agreement on (UserHandle,RpID,AAGUID) with FA
    """

    def __init__(self):
        AllQueries.__init__(self)
        self.all_queries.append(Query("S-skat", "query secret skat.\n"))
        self.all_queries.append(Query("A5", "query u:UserHandle, r:RpID, a:AAGUID, c:bitstring, pkau:spkey; "
                                                  "inj-event(Server_Finish_Reg(u,r,a,c,pkau)) ==> "
                                                  "inj-event(Client_Init_Reg(u,r)).\n"))
        self.all_queries.append(Query("A6", "query u:UserHandle, r:RpID, a:AAGUID, c:bitstring, pkau:spkey; "
                                                  "inj-event(Server_Finish_Reg(u,r,a,c,pkau)) ==> "
                                                  "inj-event(Authnr_Finish_Reg(u,r,a,c,pkau)).\n"))


class RegServerQueries(AllQueries):
    """
    As for using server-side storage authenticators in registration
    1. wrapping key wk are used
    2. attestation private key should be protected
    3. the authentication property A5: RP obtain injective agreement on (UserHandle,RpID,AAGUID,CreID) with FC
    4. the authentication property A6: RP obtain injective agreement on (UserHandle,RpID,AAGUID) with FA
    """

    def __init__(self):
        AllQueries.__init__(self)
        self.all_queries.append(Query("S-skat", "query secret skat.\n"))
        self.all_queries.append(Query("S-wk", "query secret wk.\n"))
        self.all_queries.append(Query("A5", "query u:UserHandle, r:RpID, a:AAGUID, c:bitstring, pkau:spkey; "
                                                  "inj-event(Server_Finish_Reg(u,r,a,c,pkau)) ==> "
                                                  "inj-event(Client_Init_Reg(u,r)).\n"))
        self.all_queries.append(Query("A6", "query u:UserHandle, r:RpID, a:AAGUID, c:bitstring, pkau:spkey; "
                                                  "inj-event(Server_Finish_Reg(u,r,a,c,pkau)) ==> "
                                                  "inj-event(Authnr_Finish_Reg(u,r,a,c,pkau)).\n"))


class AuthClientQueries(AllQueries):
    """
    As for using client-side storage authenticators in authentication
    1. the authentication property A1: RP obtain injective agreement on (UserHandle,RpID,AAGUID,CreID) with FA
    """
    def __init__(self):
        AllQueries.__init__(self)
        self.all_queries.append(Query("A1", "query u:UserHandle, r:RpID, a:AAGUID, c:bitstring;"
                                                  "inj-event(Server_Finish_Auth(u,r,a,c)) ==> "
                                                  "inj-event(Authnr_Finish_Auth(u,r,a,c)).\n"))


class AuthClientTrQueries(AllQueries):
    """
    As for using client-side storage authenticators in transaction authorization
    1. the transaction data should be protected
    2. the authentication property A1: RP obtain injective agreement on (UserHandle,RpID,AAGUID,CreID) with FA
    3. the authentication property A2: RP obtain injective agreement on (Transaction) with FA
    """
    def __init__(self):
        AllQueries.__init__(self)
        self.all_queries.append(Query("S-tr", "query secret Tr.\n"))
        self.all_queries.append(Query("A1", "query u:UserHandle, r:RpID, a:AAGUID, c:bitstring;"
                                                  "inj-event(Server_Finish_Auth(u,r,a,c)) ==> "
                                                  "inj-event(Authnr_Finish_Auth(u,r,a,c)).\n"))
        self.all_queries.append(Query("A2",  "query tr:Transaction; inj-event(Server_Finish_Tr(tr)) ==> "
                                                 "inj-event(Authnr_Finish_Tr(tr)).\n"))


class AuthServerQueries(AllQueries):
    def __init__(self):
        AllQueries.__init__(self)
        self.all_queries.append(Query("S-wk", "query secret wk.\n"))
        self.all_queries.append(Query("A1", "query u:UserHandle, r:RpID, a:AAGUID, c:bitstring;"
                                                  "inj-event(Server_Finish_Auth(u,r,a,c)) ==> "
                                                  "inj-event(Authnr_Finish_Auth(u,r,a,c)).\n"))


class AuthServerTrQueries(AllQueries):
    def __init__(self):
        AllQueries.__init__(self)
        self.all_queries.append(Query("S-wk", "query secret wk.\n"))
        self.all_queries.append(Query("S-tr", "query secret tr.\n"))
        self.all_queries.append(Query("A1", "query u:UserHandle, r:RpID, a:AAGUID, c:bitstring;"
                                                  "inj-event(Server_Finish_Auth(u,r,a,c)) ==> "
                                                  "inj-event(Authnr_Finish_Auth(u,r,a,c)).\n"))
        self.all_queries.append(Query("A2", "query tr:Transaction; inj-event(Server_Finish_Tr(tr)) ==> "
                                                 "inj-event(Authnr_Finish_Tr(tr)).\n"))


# AllEntities and AllFields are different from AllTypes and AllQueries
# permutation and combination in AllEntities and AllFields
# copy in AllTypes and AllQueries
class AllEntities:
    """
    a parent class for all possible combinations of malicious entities
    you can just write all the possible malicious in subclass for each phase(reg/auth)
    this parent class will generate all the combinations.
    version2 is a reduce plan
    """

    def __init__(self):
        self.all_entities = []  # all alternatives
        self.entities = []      # all combinations of the alternatives

    # get all the combinations of the malicious entities
    # range(5) = [0,1,2,3,4]
    def get_all_scenes(self):
        # i = 0,1,2,3,4,...,len(all_entities)
        for i in range(len(self.all_entities) + 1):
            # get the subset of [0,1,...,len(self.all_entities)] with i members
            # row_num is the a single subset
            for row_num in itertools.combinations(range(len(self.all_entities)), i):
                temp = []  # all the combinations
                for j in row_num:  # j is the member in row_num, the index in [0,1...,len(self.all_entities)]
                    temp.append(self.all_entities[j])
                self.entities.append(Entities(temp, row_num))

    # if all_entities = [A,B,C,D]
    # the result is [[],[A],[A,B],[A,B,C],[A,B,C,D]]
    def get_all_scenes_version2(self):
        for i in range(len(self.all_entities) + 1):
            temp_combination = []
            for j in range(i):
                temp_combination.append(self.all_entities[j])
            self.entities.append(Entities(temp_combination, range(i)))

    def size(self):
        return len(self.entities)

    def get(self, i):
        return self.entities[i]


class RegEntities(AllEntities):
    def __init__(self):
        AllEntities.__init__(self)
        self.all_entities = []
        self.all_entities.append("Reg_Authnr(aaguid, skat, pkat, wk, cP, au_type,ctap_type)|\n")
        self.all_entities.append("Reg_Client(uHandle, pWord, CR, cP, ctap_type)|\n")
        self.all_entities.append("Reg_Client(uHandle, pWord, cP, CA, ctap_type)|\n")
        self.all_entities.append("Reg_Client(uHandle, pWord, cP, cP, ctap_type)|\n")
        self.all_entities.append("Reg_Server(rpid, uHandle, pWord,cP)|\n")
        self.get_all_scenes()


class RegEntitiesV2(AllEntities):
    def __init__(self):
        AllEntities.__init__(self)
        self.all_entities = []
        self.all_entities.append("Reg_Client(uHandle, pWord, CR, cP, ctap_type)| (*malicious-Authnr*)\n")
        self.all_entities.append(
            "Reg_Authnr(aaguid, skat, pkat, wk, cP, au_type, ctap_type)"
            "|Reg_Server(rpid, uHandle, pWord,cP)| (*malicious-Client*)\n")
        self.all_entities.append("Reg_Client(uHandle, pWord, cP, CA, ctap_type)| (*malicious-RP*)\n")
        self.get_all_scenes()


class AuthEntities(AllEntities):
    def __init__(self):
        AllEntities.__init__(self)
        self.all_entities = []
        self.all_entities.append("Auth_Authnr(aaguid,wk,cP,tr_type,au_type,ctap_type)|\n")
        self.all_entities.append("Auth_Client(uHandle,CR,cP,tr_type,ctap_type)|\n")
        self.all_entities.append("Auth_Client(uHandle,cP,CA,tr_type,ctap_type)|\n")
        self.all_entities.append("Auth_Client(uHandle,cP,cP,tr_type,ctap_type)|\n")
        self.all_entities.append("Auth_Server(rpid,uHandle,Tr,cP,tr_type)| \n")
        self.get_all_scenes()


class AuthEntitiesV2(AllEntities):
    def __init__(self):
        AllEntities.__init__(self)
        self.all_entities = []
        self.all_entities.append("Auth_Client(uHandle,CR,cP,tr_type,ctap_type)| (*malicious-Authnr*)\n")
        self.all_entities.append(
            "Auth_Authnr(aaguid,wk,cP,tr_type, au_type,ctap_type)|"
            "Auth_Server(rpid,uHandle,Tr,cP,tr_type)| (*malicious-Client*)\n")
        self.all_entities.append("Auth_Client(uHandle,cP,CA,tr_type,ctap_type)| (*malicious-RP*)\n")
        self.get_all_scenes()


class AllFields:
    """
    A parent class for all possible combinations of the compromised fields
    t
    this file does not consider the compromise of the fields since it lead to too much time to run
    if you want to analyze the case when there are fields being compromised use "get_all_scenes_version2"
    """

    def __init__(self):
        self.all_fields = []  # all possibly leaked fields
        self.fields = []  # all combinations of the possibly leaked fields
        self.all_fields.append("out(cP,wk);\n")

    # get all the combinations of leaked fields
    def get_all_scenes(self):
        if Setting.analyze_flag == "simple":
            # a simplified version with no leaked fields
            print("analyzing the scenarios where no fields are comprimised.")
            self.fields = [Fields(["(* no fields being compromised *)\n"])]
        else:
            print("analyzing the full scenarios.")
            self.fields = []
            for i in range(len(self.all_fields) + 1):
                # get the subsets with i(0,1,2,3,4) items
                # pre a single subset
                for subset in itertools.combinations(self.all_fields, i):
                    self.fields.append(Fields(subset))

    def size(self):
        return len(self.fields)

    def get(self, i):
        return self.fields[i]


class RegFields(AllFields):
    def __init__(self):
        AllFields.__init__(self)
        self.all_fields.append("out(cP,skat);\n")
        self.get_all_scenes()


class AuthFields(AllFields):
    def __init__(self):
        AllFields.__init__(self)
        self.all_fields.append("out(cP,skau);\n")
        self.all_fields.append("out(cP,authcntr);\n")
        self.all_fields.append("out(cP,creid);\n")
        self.get_all_scenes()


class Case:
    """
    this class define a specific case with
    phase   : registration or authentication
    type    : the type of the authenticator
    query   : queries of this case
    fields  : compromised fields of this case
    entities: malicious entities of this case
    lines   : the already read lines
    """
    def __init__(self, p, types, ctap, q, f, e, lines, t_row, f_row, e_c_row, e_c_row_1 ,e_noc_row):
        self.phase = p                 # reg_(client/server),auth_(client/server)_(em/simple/generic)
        self.type = types
        self.ctap = ctap
        self.query = q
        self.fields = f
        self.entities = e
        self.lines = lines             # initial lines in Reg.pv or Auth.pv
        self.type_set_row = t_row      # the row inserting the definition of type
        self.fields_set_row = f_row    # the row inserting the definition of compromised fields
        self.entities_ctap_set_row = e_c_row  # the row inserting the definition of compromised entities
        self.entities_ctap_set_row_1 = e_c_row_1
        self.entities_noctap_set_row = e_noc_row  # the row inserting the definition of compromised entities
        self.query_path = Setting.ScriptPath + "TEMP-" + p + "-" + q.name + "-" + f.name + "-" + e.name + ".pv"
        self.state = ""
        self.result = ""

    def write_file(self, if_delete_parallel):
        """
        write the query file for proverif to verify
        'if_delete_parallel = true' simplifies the verification by removing "!" in the code
        """
        f2 = open(self.query_path, "w")
        analyze_lines = []
        if if_delete_parallel:  # if true, then remove ! to speed up analyzing
            for i in range(len(self.lines)):
                analyze_lines.append(self.lines[i].replace('!', ''))
        else:
            analyze_lines = self.lines
        f2.writelines(self.query.write)
        for i in range(len(analyze_lines)):
            if i == self.type_set_row:      # set au_type and tr_type
                f2.writelines(self.ctap.write)
                f2.writelines(self.type.write)
            if i == self.fields_set_row:    # set compromised fields
                f2.writelines(self.fields.write)
            if i == self.entities_noctap_set_row:  # set compromised entities
                if self.ctap.name == 'noCTAP':
                    f2.writelines(self.entities.write)
            if i == self.entities_ctap_set_row_1:
                if self.ctap.name != 'noCTAP':
                    if 0 in self.entities.row_numbers:
                        f2.writelines('CTAP_Authnr(G, PIN, cP, ctap_type)|\n')
                    if 1 in self.entities.row_numbers:
                        f2.writelines('CTAP_Client(G, PIN, cP, ctap_type)|\n')
            if i == self.entities_ctap_set_row:
                if self.ctap.name != 'noCTAP':
                    f2.writelines(self.entities.write)
            f2.writelines(analyze_lines[i])
        f2.close()

    def analyze(self):
        # carry out analysis and get result by proverif
        self.write_file(True)
        ret, result = self.proverif()
        if ret == 'false':
            self.state = ret
            f = open(self.query_path)
            content = f.readlines()
            f.close()
            os.remove(self.query_path)
            return ret, result, content
        else:
            self.write_file(False)
            ret, result = self.proverif()
            self.state = ret
            f = open(self.query_path)
            content = f.readlines()
            f.close()
            os.remove(self.query_path)
            return ret, result, content

    # call proverif for verification
    def proverif(self):
        # cmd command for verification
        output = Popen('proverif -lib ' + Setting.LibPath + ' ' + self.query_path, stdout=PIPE, stderr=PIPE)
        timer = Timer(30, lambda process: process.kill(), [output])
        try:
            timer.start()
            stdout, stderr = output.communicate()
        finally:
            timer.cancel()
        i = stdout[0:-10].rfind(b'--------------------------------------------------------------')
        result = stdout[i:-1]
        if result == b"" or len(result) == 0:
            result = stdout[-1000:-1]
            if result.find(b'a trace has been found.'):
                ret = 'false'
            elif result.find(b'trace'):
                ret = 'mayfalse'
            else:
                ret = 'tout'
        elif result.find(b'error') != -1:
            ret = 'error'
        elif result.find(b'false') != -1:
            ret = 'false'
        elif result.find(b'hypothesis:') != -1:
            ret = 'trace'
        elif result.find(b'prove') != -1:
            ret = 'prove'
        elif result.find(b'true') != -1:
            ret = 'true'
        else:
            ret = 'tout'
        self.state = ret
        self.result = result
        return ret, result


class Generator:
    """
    p, t, q, f, e, lines, t_row, i_row
    set the phase, types, queries, fields, entities, lines, type/insert rows for a specific case.
    besides, this class maintain a secure sets to speed up the case which is subset
    find a secure set: with compromised: A, B, C, D
    then the set with compromised subset of (A, B, C, D) is also secure
    """

    def __init__(self, phase):
        self.secure_sets = []
        self.insecure_sets = []
        if phase == "reg_client":
            self.phase = "reg_client"
            self.types = RegClientTypes()
            self.ctap = AllCTAPType()
            self.queries = RegClientQueries()
            self.fields = RegFields()
            self.entities = RegEntities()
            self.lines = self.read_file()
            self.type_set_row = Setting.set_type_row                        # indicate type
            self.fields_set_row = Setting.reg_fields_row                    # insert compromised fields
            self.entities_noctap_set_row = Setting.reg_entities_noctap_row  # insert compromised entities in no ctap case
            self.entities_ctap_set_row = Setting.reg_entities_ctap_row      # insert compromised entities in ctap case
            self.entities_ctap_set_row_1 = Setting.reg_entities_ctap_row_1
        elif phase == "reg_server":
            self.phase = "reg_server"
            self.types = RegServerTypes()
            self.ctap = AllCTAPType()
            self.queries = RegServerQueries()
            self.fields = RegFields()
            self.entities = RegEntities()
            self.lines = self.read_file()
            self.type_set_row = Setting.set_type_row      # indicate type
            self.fields_set_row = Setting.reg_fields_row      # insert compromised fields
            self.entities_noctap_set_row = Setting.reg_entities_noctap_row  # insert compromised entities in no ctap case
            self.entities_ctap_set_row = Setting.reg_entities_ctap_row      # insert compromised entities in ctap case
            self.entities_ctap_set_row_1 = Setting.reg_entities_ctap_row_1
        elif phase == "auth_client_em":
            self.phase = "auth_client_em"
            self.types = AuthClientEmpTypes()
            self.ctap = AllCTAPType()
            self.queries = AuthClientQueries()
            self.fields = AuthFields()
            self.entities = AuthEntities()
            self.lines = self.read_file()
            self.type_set_row = Setting.set_type_row                         # indicate type
            self.fields_set_row = Setting.auth_fields_row                    # insert compromised fields
            self.entities_noctap_set_row = Setting.auth_entities_noctap_row  # insert compromised entities in no ctap case
            self.entities_ctap_set_row = Setting.auth_entities_ctap_row      # insert compromised entities in ctap case
            self.entities_ctap_set_row_1 = Setting.auth_entities_ctap_row_1 
        elif phase == "auth_client_sim":
            self.phase = "auth_client_sim"
            self.types = AuthClientSimTypes()
            self.ctap = AllCTAPType()
            self.queries = AuthClientTrQueries()
            self.fields = AuthFields()
            self.entities = AuthEntities()
            self.lines = self.read_file()
            self.type_set_row = Setting.set_type_row      # indicate type
            self.fields_set_row = Setting.auth_fields_row      # insert compromised fields
            self.entities_noctap_set_row = Setting.auth_entities_noctap_row  # insert compromised entities in no ctap case
            self.entities_ctap_set_row = Setting.auth_entities_ctap_row      # insert compromised entities in ctap case
            self.entities_ctap_set_row_1 = Setting.auth_entities_ctap_row_1
        elif phase == "auth_client_gen":
            self.phase = "auth_client_gen"
            self.types = AuthClientGenTypes()
            self.ctap = AllCTAPType()
            self.queries = AuthClientTrQueries()
            self.fields = AuthFields()
            self.entities = AuthEntities()
            self.lines = self.read_file()
            self.type_set_row = Setting.set_type_row      # indicate type
            self.fields_set_row = Setting.auth_fields_row      # insert compromised fields
            self.entities_noctap_set_row = Setting.auth_entities_noctap_row  # insert compromised entities in no ctap case
            self.entities_ctap_set_row = Setting.auth_entities_ctap_row      # insert compromised entities in ctap case
            self.entities_ctap_set_row_1 = Setting.auth_entities_ctap_row_1
        elif phase == "auth_server_em":
            self.phase = "auth_server_em"
            self.types = AuthServerEmpTypes()
            self.ctap = AllCTAPType()
            self.queries = AuthServerQueries()
            self.fields = AuthFields()
            self.entities = AuthEntities()
            self.lines = self.read_file()
            self.type_set_row = Setting.set_type_row      # indicate type
            self.fields_set_row = Setting.auth_fields_row      # insert compromised fields
            self.entities_noctap_set_row = Setting.auth_entities_noctap_row  # insert compromised entities in no ctap case
            self.entities_ctap_set_row = Setting.auth_entities_ctap_row      # insert compromised entities in ctap case
            self.entities_ctap_set_row_1 = Setting.auth_entities_ctap_row_1
        elif phase == "auth_server_sim":
            self.phase = "auth_server_sim"
            self.types = AuthServerSimTypes()
            self.ctap = AllCTAPType()
            self.queries = AuthServerTrQueries()
            self.fields = AuthFields()
            self.entities = AuthEntities()
            self.lines = self.read_file()
            self.type_set_row = Setting.set_type_row  # indicate type
            self.fields_set_row = Setting.auth_fields_row      # insert compromised fields
            self.entities_noctap_set_row = Setting.auth_entities_noctap_row  # insert compromised entities in no ctap case
            self.entities_ctap_set_row = Setting.auth_entities_ctap_row      # insert compromised entities in ctap case
            self.entities_ctap_set_row_1 = Setting.auth_entities_ctap_row_1
        elif phase == "auth_server_gen":
            self.phase = "auth_server_gen"
            self.types = AuthServerGenTypes()
            self.ctap = AllCTAPType()
            self.queries = AuthServerTrQueries()
            self.fields = AuthFields()
            self.entities = AuthEntities()
            self.lines = self.read_file()
            self.type_set_row = Setting.set_type_row      # indicate type
            self.fields_set_row = Setting.auth_fields_row      # insert compromised fields
            self.entities_noctap_set_row = Setting.auth_entities_noctap_row  # insert compromised entities in no ctap case
            self.entities_ctap_set_row = Setting.auth_entities_ctap_row      # insert compromised entities in ctap case
            self.entities_ctap_set_row_1 = Setting.auth_entities_ctap_row_1
        self.reverse_f_e()  # reverse the combinations
        self.t_nums = self.types.size()
        self.q_nums = self.queries.size()
        self.c_nums = self.ctap.size()
        self.f_nums = self.fields.size()    # the num of compromises fields
        self.e_nums = self.entities.size()  # the num of compromises entities
        self.c_cur = 0
        self.t_cur = 0
        self.q_cur = 0
        self.f_cur = 0
        self.e_cur = -1

    def read_file(self):
        if self.phase == "reg_server":
            pv_file = open(Setting.RegPath)
            lines = pv_file.readlines()
        elif self.phase == "reg_client":
            pv_file = open(Setting.RegPath)
            lines = pv_file.readlines()
        else:
            pv_file = open(Setting.AuthPath)
            lines = pv_file.readlines()
        pv_file.close()
        return lines

    def generator_case(self):
        if self.increase() is False:
            return False, 0
        else:
            p = self.phase
            cur_type = self.types.get(self.t_cur)
            q = self.queries.get(self.q_cur)
            f = self.fields.get(self.f_cur)
            e = self.entities.get(self.e_cur)
            c = self.ctap.get(self.c_cur)
            case = Case(p, cur_type, c, q, f, e, self.lines,
                        self.type_set_row, self.fields_set_row, self.entities_ctap_set_row,self.entities_ctap_set_row_1,self.entities_noctap_set_row)
            return True, case

    def increase(self):

        if self.e_cur >= self.e_nums - 1:
            self.e_cur = 0
            self.secure_sets.clear()
            if self.f_cur >= self.f_nums - 1:
                self.f_cur = 0
                if self.q_cur >= self.q_nums - 1:
                    self.q_cur = 0
                    if self.c_cur >= self.c_nums - 1:
                        self.c_cur = 0
                        if self.t_cur >= self.t_nums - 1:
                            return False
                        else:
                            self.t_cur = self.t_cur + 1
                    else:
                        self.c_cur = self.c_cur + 1
                else:
                    self.q_cur = self.q_cur + 1
            else:
                self.f_cur = self.f_cur + 1
        else:
            # the first call of increase, e_cur from -1 to 0
            # other cur nums are 0
            self.e_cur = self.e_cur + 1
        return True

    def reverse_f_e(self):
        """
        to find out the minimum assumptions
        we start from the full set of compromised fields and entities
        then iterate over its subset
        """
        self.fields.fields.reverse()
        self.entities.entities.reverse()

    def this_case_is_secure(self):  # add a secure sets
        self.secure_sets.append(self.entities.get(self.e_cur).row_numbers)

    def jump_if_its_secure(self):
        for secure_case in self.secure_sets:
            cur_case = self.entities.get(self.e_cur).row_numbers
            if set(cur_case).issubset(set(secure_case)):
                return True
        return False

    def this_case_is_insecure(self):
        self.insecure_sets.append(self.entities.get(self.e_cur).row_numbers)

    def jump_if_its_insecure(self):
        for insecure_case in self.insecure_sets:
            cur_case = self.entities.get(self.e_cur).row_numbers
            if set(cur_case).issubset(set(insecure_case)):
                return True
        return False


def analysis(phase, log):
    """
    giving the phase and a log file name, then start analysis
    1.  initialize a Generator: set the phase, types, queries, fields, entities, lines, type/insert rows
        of a certain authenticator and a certain phase
        a. fields and entities contain all possible compromised alternatives[all_] and combinations[fields/entities]
        b. self.t_cur = 0 record the current type under analyzing
        c. self.q_cur = 0 record the current query under analyzing
        d. self.f_cur = 0  record the current number of compromised fields under analyzing
        e. self.e_cur = -1 record the current number of compromised entities under analyzing
    2.  call function in Class Generator: generator_case() to constitute a certain case
        in generator_case(), it calls increase() to update the cur numbers
        cur numbers are indexes of the list, so compared with num-1
        the logic is: entities, fields, queries, types
        after going through all the cases, the return: r = False
    3.  review the current case to determine if it is safe/unsafe
        if the initial check cannot be confirmed, call case.analyze()
    """
    gen = Generator(phase)
    count = 0
    while True:
        r, case = gen.generator_case()
        if r is False:
            break
        if gen.jump_if_its_secure():
            # ljust(n)Returns the left justified string
            # and fills in the new string with spaces of the specified length
            msg = str(count).ljust(5) + phase.ljust(4) + "skipping for secure sets"
        elif gen.jump_if_its_insecure():
            msg = str(count).ljust(5) + phase.ljust(4) + "skipping for noprove sets"
        else:
            msg = str(count).ljust(5) + phase.ljust(4)
            ret, result, content = case.analyze()
            if ret == 'true':
                gen.this_case_is_secure()
                msg += "  true"
            else:
                msg += "  " + ret

            msg += " type "
            msg += case.type.name.ljust(4)
            msg += " query "
            msg += case.query.name.ljust(4)
            msg += " ctap "
            msg += case.ctap.name.ljust(5)
            msg += str(case.fields.name).ljust(9)
            msg += " "
            msg += str(case.entities.name).ljust(8)
            if ret != 'false':  # only write the analysis file for true cases
                if not os.path.exists(Setting.ResultPath + case.phase + "/" + case.ctap.name + "/"+ case.type.name + "/" + case.query.name):
                    os.makedirs(Setting.ResultPath + case.phase + "/" + case.ctap.name + "/" + case.type.name + "/" + case.query.name)
                f = open(Setting.ResultPath + case.phase + "/" + case.ctap.name + "/" + case.type.name + "/" + case.query.name + "/" + msg,
                         "w")
                f.writelines(content)
                f.writelines(str(result[-1000:-1]))
                f.close()
        count = count + 1
        write_log(msg, log)
        log.flush()


def write_log(msg, log):
    print(msg, file = log)


def print_help():
    print("usage: [-help] [-h] [-target <target_name>] [-t <target_name>]")
    print("Options and arguments:")
    print("-h/-help  : show help informations.")
    print("-s/-simple :  analyze cases where no fields are leaked, this argument will reduce the analyzing time but give incomplete results. If don't specify, then analyze all cases by default.")
    print("-t/-target  : verify a specific phase, if don't specify, then verify all phases. ")
    print("    The candidates arguments are:")
    print("       reg_client      : to analyze registration process with client-side storage authenticators.")
    print("       reg_server      : to analyze registration process with server-side storage authenticators.")
    print("       auth_client_em  : to analyze authentication process with client-side storage authenticators.")
    print("       auth_client_sim : to analyze simple transaction authorization process with client-side storage authenticators.")
    print("       auth_client_gen : to analyze generic transaction authorization process with client-side storage authenticators.")
    print("       auth_server_em  : to analyze authentication process with server-side storage authenticators.")
    print("       auth_server_sim : to analyze simple transaction authorization process with server-side storage authenticators.")
    print("       auth_server_gen : to analyze generic transaction authorization process with server-side storage authenticators.")

if __name__ == "__main__":
    Setting.initiate()
    log1 = open(Setting.LogPath1, mode='w+', encoding='utf-8')
    log2 = open(Setting.LogPath2, mode='w+', encoding='utf-8')
    log3 = open(Setting.LogPath3, mode='w+', encoding='utf-8')
    log4 = open(Setting.LogPath4, mode='w+', encoding='utf-8')
    log5 = open(Setting.LogPath5, mode='w+', encoding='utf-8')
    log6 = open(Setting.LogPath6, mode='w+', encoding='utf-8')
    log7 = open(Setting.LogPath7, mode='w+', encoding='utf-8')
    log8 = open(Setting.LogPath8, mode='w+', encoding='utf-8')
    t1 = threading.Thread(target=analysis, args=("reg_client", log1))
    t2 = threading.Thread(target=analysis, args=("reg_server", log2))
    t3 = threading.Thread(target=analysis, args=("auth_client_em", log3))
    t4 = threading.Thread(target=analysis, args=("auth_client_sim", log4))
    t5 = threading.Thread(target=analysis, args=("auth_client_gen", log5))
    t6 = threading.Thread(target=analysis, args=("auth_server_em", log6))
    t7 = threading.Thread(target=analysis, args=("auth_server_sim", log7))
    t8 = threading.Thread(target=analysis, args=("auth_server_gen", log8))
    thread_list = [t1, t2, t3, t4, t5, t6, t7, t8]  # run all the phases
    try:
        options, args = getopt.getopt(sys.argv[1:], "-h-help-t:-target:-s-simple", ["help", "target="])
    except getopt.GetoptError:
        print("wrong option!")
        print_help()
        sys.exit()
    for option, value in options:
        if option in ("-h", "-help", "--help"):
            print_help()
            sys.exit()
        elif option in ("-t","--t","--target","-target"): # if specific which phase to analyze, then clean the tlist
            thread_list = []
            if str(value) == "reg_client":
                thread_list.append(t1)
            elif str(value) == "reg_server":
                thread_list.append(t2)
            elif str(value) == "auth_client_em":
                thread_list.append(t3)
            elif str(value) == "auth_client_sim":
                thread_list.append(t4)
            elif str(value) == "auth_client_gen":
                thread_list.append(t5)
            elif str(value) == "auth_server_em":
                thread_list.append(t6)
            elif str(value) == "auth_server_sim":
                thread_list.append(t7)
            elif str(value) == "auth_server_gen":
                thread_list.append(t8)
            else:
                print("wrong argument!")
        elif option in ("-simple", "-s"):
            Setting.analyze_flag = "simple"
        else:
            print("wrong option!")
    for t in thread_list:
        t.start()
    for t in thread_list:
        t.join()
    log1.close()
    log2.close()
    log3.close()
    log4.close()
    log5.close()
    log6.close()
    log7.close()
    log8.close()
