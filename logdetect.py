#!/usr/bin/env python 
#############################################################################
##                                                                         ##
##  Copyleft by WebNuLL < webnull.www at gmail dot com >                   ##
##                                                                         ##
## This program is free software; you can redistribute it and/or modify it ##
## under the terms of the GNU General Public License version 3 as          ##
## published by the Free Software Foundation; version 3.                   ##
##                                                                         ##
## This program is distributed in the hope that it will be useful, but     ##
## WITHOUT ANY WARRANTY; without even the implied warranty of              ##
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       ##
## General Public License for more details.                                ##
##                                                                         ##
#############################################################################

import os, sys, getopt, re, logging, time, inspect, base64, ftplib, datetime, time

if sys.version_info[0] >= 3:
    import configparser
else:
    import ConfigParser as configparser

from time import strftime, localtime
from threading import Thread

# if there is no sqlite3 installed in system it will be turned off safely
try:
    import sqlite3
except Exception:
    pass

sys.path.append("/etc/logdetect/modules/")

""" Logdetect - Parse logs and take actions in real time.
     Configuralbe via ini files, parsers and filters.
     Works by detecting threats and identifing its level, if user reaches maximum level of warnings will be banned on iptables or in another way using custom command.
"""

class MySum:
    def __init__(self):
        self.count = 0

    def step(self, value):
        self.count += value

    def finalize(self):
        return self.count

class LogThread(Thread):
    def __init__(self,cmd,Plugin,sObject):
        Thread.__init__(self) # initialize thread
        self.Plugin = Plugin
        self.sObject = sObject
        self.status = "Idle"
        self.cmd = cmd

    def run(self):
        exec(self.cmd)

class logdatabase:
    socket = ""
    cursor = ""
    parent = ""

    def createEmptyDB(self):
        self.parent.output("Creating new database")
        self.cursor.execute("CREATE TABLE `ld_intruders` (uid varchar(60) primary key, points int(10), banned int(1), reason varchar(60));")
        self.cursor.execute("CREATE TABLE `ld_files` (id int(60) primary key, extension varchar(60), file varchar(60), lastline text, lastmodified int(40), position int(30));")
        self.socket.commit()

    def connectDB(self):
        # if database was not set, skip it
        if not 'database' in self.parent.Options['settings']:
            self.socket = ""
            return

        newDB = False

        try:
            if not os.path.isfile(self.parent.Options['settings']['database']):
                newDB = True

            self.socket = sqlite3.connect(self.parent.Options['settings']['database'], check_same_thread = False)
            self.socket.create_aggregate("mysum", 1, MySum)
            self.socket.isolation_level = None
            self.socket.row_factory = self.dict_factory
            self.cursor = self.socket.cursor()

            if newDB == True:
                self.createEmptyDB()

        except Exception as e:
            self.parent.output("WARNING, NO DATABASE LOADED")
            self.parent.output("logdatabase: "+str(e))
            return

    # save file parsing position to database
    def setPosition(self, File, Extension, Position, LastLine, LastModification):
        if self.socket == "":
            return

        SQL = ""

        try:
            query = self.cursor.execute('SELECT * FROM `ld_files` WHERE `extension`="'+Extension+'" AND `file`="'+File+'";')

            if query.fetchone() == None:
                SQL = "INSERT INTO `ld_files` (id, extension, file, lastline, lastmodified, position) VALUES (NULL, '"+str(Extension)+"', '"+str(File)+"', '"+base64.b64encode(str(LastLine))+"', '"+str(LastModification)+"', '"+str(Position)+"');"
            else:
                SQL = 'UPDATE `ld_files` SET `extension`="'+str(Extension)+'", `file`="'+str(File)+'", `lastline`="'+base64.b64encode(str(LastLine))+'", `lastmodified`="'+str(LastModification)+'", `position`="'+str(Position)+'" WHERE `extension`="'+Extension+'" and `file`="'+File+'"'

            if self.parent.Options['debug'] == True:
                self.parent.output("Executing query \""+SQL+"\"")
            query = self.cursor.execute(SQL)
        except Exception as e:
            self.parent.output("Failed to execute query '"+SQL+"', err='"+str(e)+"'")

        return SQL

    def dict_factory(self, cursor, row):
        d = {}
        for idx, col in enumerate(cursor.description):
            d[col[0]] = row[idx]
        return d

    def getPosition(self, File, Extension):
        if self.socket == "":
            return

        try:
            query = self.cursor.execute('SELECT * FROM `ld_files` WHERE `extension`="'+Extension+'" AND `file`="'+File+'";')
            Array = query.fetchone()            

            if not Array == None:
                return {'lastline': base64.b64decode(Array['lastline']), 'lastmodified': int(Array['lastmodified']), 'position': int(Array['position'])}
            else:
                return False

        except Exception as e:
            self.parent.output("Failed to execute query '"+SQL+"', err='"+str(e)+"'")

class logdetect:
    def printUsage(self):
        """ Usage """

        print("logdetect - Parse logs and take actions in real time.")
        print(" Extensible by filters and parsers, handles Apache, lighttpd and more logs")
        print("")
        print("Usage: logdetect [option] [long GNU option]")
        print("")
        print("Valid options:")
        print("  -h, --help             : display this help")
        print("  -f, --fork             : fork to background and work as daemon")
        print("  -d, --debug            : switch to debug log level")
        print("  -c, --config=          : load config at startup")
        print("  -e, --extensions-dir=  : choose extensions directory, default is /etc/logdetect/modules/")
        print("")
        sys.exit(0)



    def daemonize (self, stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):
        '''This forks the current process into a daemon.
        The stdin, stdout, and stderr arguments are file names that
        will be opened and be used to replace the standard file descriptors
        in sys.stdin, sys.stdout, and sys.stderr.
        These arguments are optional and default to /dev/null.
        Note that stderr is opened unbuffered, so
        if it shares a file with stdout then interleaved output
        may not appear in the order that you expect.
        '''

        # Do first fork.
        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)   # Exit first parent.
        except OSError as e:
            sys.stderr.write ("fork #1 failed: (%d) %s\n" % (e.errno, e.strerror) )
            sys.exit(1)

        # Decouple from parent environment.
        os.chdir("/")
        os.umask(0)
        os.setsid()

        # Do second fork.
        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)   # Exit second parent.
        except OSError as e:
            sys.stderr.write ("fork #2 failed: (%d) %s\n" % (e.errno, e.strerror) )
            sys.exit(1)

        # Redirect standard file descriptors.
        si = open(stdin, 'r')
        so = open(stdout, 'a+')
        se = open(stderr, 'a+', 0)
        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())

    # Global variables
    Options = dict()
    Options['modules_dir'] = "/etc/logdetect/modules/"
    Options['fork'] = False
    Options['debug'] = False
    Options['config'] = "/etc/logdetect/logdetect.conf"
    Options['logging'] = False
    Extensions = dict()
    ExtensionInfo = dict()
    Filters = dict()
    Intruders = dict()




    def output(self, msg):
        """ Output messages to console or to log file """

        if self.Options['logging'] == True:
            self.log.info(strftime("%d/%m/%Y %H:%M:%S", localtime())+", "+inspect.stack()[1][3]+": "+msg)
        
        if self.Options['fork'] == False:
            print(strftime("%d/%m/%Y %H:%M:%S", localtime())+", "+inspect.stack()[1][3]+": "+msg)




    def GNUOpt(self):
        try:
            opts, args = getopt.getopt(sys.argv[1:], 'hfdc:e:', ['help', 'fork', 'debug', 'config=', 'extensions-dir='])
        except getopt.error as msg:
            print(msg)
            print("Type "+sys.argv[0]+" --help for usage")
            sys.exit(2)

        # process options
        for o, a in opts:
            if o in ('-h', '--help'):
                self.printUsage()
                sys.exit(2)
            if o in ('-f', '--fork'):
                self.Options['fork'] = True

            if o in ('-d', '--debug'):
                self.Options['debug'] = True

            if o in ('-e', '--extensions-dir'):
                self.Options['modules_dir'] = a

            if o in ('-c', '--config'):
                self.Options['config'] = a





    def parseExtension(self, extension):
        """ Parsing extensions from /etc/logdetect/modules/
            Needed files: 
                __init.py - to use extension as Python module
                main.py - log parsing class
                ini files - filters to use
        """

        if not os.path.isdir(self.Options['modules_dir']+extension+"/"):
            self.output("Cannot load extension "+extension+", details: No such directory \""+self.Options['modules_dir']+extension+"/\"")
            return

        if not os.path.isfile(self.Options['modules_dir']+extension+"/main.py"):
            self.output("Cannot load extension "+extension+", details: No main.py file found")
            return

        try:
            if self.Options['debug'] == True:
                self.output("parseExtension: Loading "+extension+" extension from "+self.Options['modules_dir']+extension+"/main.py")

            exec("import "+extension+".main as CurrentModule; self.CurrentModule = CurrentModule")
            Object = self.CurrentModule.LogdetectExtension(self)
            self.Extensions[extension] = Object
        except Exception as e:
            self.output("Error: Cannot load extension "+extension+", details: "+str(e))

        if self.Options['debug'] == True:
            self.output("parseExtension: Looking for filters in "+self.Options['modules_dir']+extension+"/")

        Files = os.listdir(self.Options['modules_dir']+extension+"/")

        # Create filters database
        self.Filters[extension] = dict()
        # Statistics
        RulesCount = 0
        VariablesCount = 0        

        for INI in Files:
            # skip __init.py and main.py
            if INI[-2:] == "py" or INI == "__init__.py" or INI == "main.py" or INI[-3:] == "pyc":
                continue

            Parser = configparser.ConfigParser()
            try:
                Parser.read(self.Options['modules_dir']+extension+"/"+INI)
            except Exception as e:
                self.output("parseExtension: Error loading filter "+INI+" from "+extension+", details: "+str(e))
                sys.exit(os.EX_CONFIG)

            Sections = Parser.sections()

            for Section in Sections:
                Options = Parser.options(Section)
                Adress = INI[:-4]+"_"+Section
                RulesCount += 1
                self.Filters[extension][Adress] = dict() 

                for Option in Options:
                    VariablesCount += 1
                    self.Filters[extension][Adress][Option] = Parser.get(Section, Option)

            self.loadWhiteList(extension)
            self.output("Finished loading "+str(RulesCount)+" rules and "+str(VariablesCount)+" variables from "+INI)
            







    def parseConfig(self, File):
        """ Parsing configuration file, loading plugins and filters """

        if not os.path.isfile(File):
            self.output("(FATAL) parseConfig: Cannot find configuration file in \""+File+"\", exiting...")
            sys.exit(os.EX_CONFIG)


        if self.Options['debug'] == True:
            self.output("parseConfig: Parsing "+File)

        Parser = configparser.ConfigParser()

        try:
            Parser.read(File)
        except Exception as e:
            self.output("Error reading "+File+", details: "+str(e))
            sys.exit(os.EX_CONFIG)

        # get all sections
        Sections = Parser.sections()
        statExtensions = 0
        statConfigSections = 0
        statVariables = 0

        for Section in Sections:
            if Section[0:6] == "module": # check if its module configuration
                if Parser.get(Section, "enabled") == "True": # is this module enabled?
                    statExtensions += 1
                    Adress = Section[7:]

                    self.ExtensionInfo[Adress] = dict()
                    Options = Parser.options(Section)

                    for Option in Options:
                        self.ExtensionInfo[Adress][Option] = Parser.get(Section, Option)

                    # initializing time-queue
                    self.ExtensionInfo[Adress]['wait'] = 0
                    self.ExtensionInfo[Adress]['last_modified'] = 0

                    if not 'timer' in self.ExtensionInfo[Adress]:
                        self.ExtensionInfo[Adress]['timer'] = 5

                    # job queue = ready (idle)
                    self.ExtensionInfo[Adress]['state'] = 'idle'

                    if not 'file' in self.ExtensionInfo[Adress]:
                        del self.ExtensionInfo[Adress]
                        self.output("parseConfig: Cannot load "+Adress+" extension, \"file\" attribute not found")
                        continue

                    self.parseExtension(Adress)
            else:
                statConfigSections += 1
                self.Options[Section] = dict()

                Options = Parser.options(Section)

                # parse other configuration variables
                for Option in Options:
                    statVariables += 1
                    self.Options[Section][Option] = Parser.get(Section, Option)

        if not 'loopinterval' in self.Options['settings']:
            self.Options['settings']['loopinterval'] = 1.0

        self.output("Loaded "+str(statExtensions)+" extension(s), "+str(statConfigSections)+" config sections and "+str(statVariables)+" configuration variables")

    def dictGetKey(self, array, key):
        if key in array:
            return array[key]
        else:
            return False



    def loadWhiteList(self, Extension):
        if self.dictGetKey(self.ExtensionInfo, 'whitelist_uid'):
            if not os.access(self.ExtensionInfo, os.R_OK):
                self.output("File \""+self.ExtensionInfo['whitelist_uid']+"\" is not readable.")
                return False

            handler = open(self.ExtensionInfo['whitelist_uid'], 'rb')
            self.ExtensionInfo['whitelist_uid_array'] = handler.readlines()
            handler.close()
            self.output("Loaded \""+str(len(self.ExtensionInfo['whitelist_uid_array']))+"\" whitelist items for \""+Extension+"\" extension.")



    def loadGlobalWhiteList(self):
        if self.dictGetKey(self.Options['settings'], 'whitelist_uid'):
            if not os.access(self.Options['settings']['whitelist_uid'], os.R_OK):
                self.output("File \""+self.Options['settings']['whitelist_uid']+"\" is not readable.")
                return False

            handler = open(self.Options['settings']['whitelist_uid'], 'rb')
            self.Options['settings']['whitelist_uid_array'] = handler.readlines()
            handler.close()
            self.output("Loaded "+str(len(self.Options['settings']['whitelist_uid_array']))+" global whitelist items.")
            


    def whiteListCheck(self, UserID, Extension):
        """ Check for adress in whitelists """

        if not self.dictGetKey(self.ExtensionInfo[Extension], 'whitelist_uid_array') == False:
            if UserID+"\n" in self.ExtensionInfo[Extension]['whitelist_uid_array']:
                if self.Options['debug'] == True:
                    self.output("Skipped uid="+UserID+", reason=Extension Whitelist")
                return True

        # if dont use global whitelist in extension
        if self.dictGetKey(self.ExtensionInfo[Extension], 'whitelist_uid_use_global') == "False" or self.dictGetKey(self.ExtensionInfo[Extension], 'whitelist_uid_use_global') == False:
            return False

        if not self.dictGetKey(self.Options['settings'], 'whitelist_uid_array') == False:
            if UserID+"\n" in self.Options['settings']['whitelist_uid_array']:
                if self.Options['debug'] == True:
                    self.output("Skipped uid="+UserID+", reason=Global Whitelist")

                return True


    def takeAction(self, Extension, Points, UserID, Problem):
        """ Add warning points to UID if attack was detected, ban if limit rearched """

        # first check the whitelists
        if self.whiteListCheck(UserID, Extension) == True:
            return

        if not str(UserID) in self.Intruders:
            self.Intruders[UserID] = dict()
            self.Intruders[UserID]['warn'] = 0
            self.Intruders[UserID]['problems'] = list()
            self.Intruders[UserID]['banned'] = False

        # points needed to ban (execute banning command)
        if self.dictGetKey(self.ExtensionInfo[Extension], 'banafter') == False:
            self.ExtensionInfo[Extension]['banafter'] = 100

        saved = False

        self.Intruders[UserID]['warn'] += int(Points)
        self.Intruders[UserID]['problems'].append(Problem)

        if self.ExtensionInfo[Extension]['banafter'] == "immediately":
            saved = True
            self.ExtensionInfo[Extension]['banafter'] = 0

        #print "WARN for "+Problem+" (+"+str(Points)+") - summary: "+str(self.Intruders[UserID]['warn'])

        if self.Intruders[UserID]['banned'] == True:
            return

        if self.Intruders[UserID]['warn'] >= int(self.ExtensionInfo[Extension]['banafter']) or self.ExtensionInfo[Extension]['banafter'] == "immediately":
            if not self.dictGetKey(self.ExtensionInfo[Extension], 'bancmd') == False:
                # prepare command
                Command = self.dictGetKey(self.ExtensionInfo[Extension], 'bancmd').replace("%UID%", UserID)
                Command = Command.replace("%REASON%", Problem)
                Command = Command.replace("%WARNINGS%", str(self.Intruders[UserID]['warn']))
                os.system(Command)

                self.output("Sending bancmd='"+Command+"' for uid="+UserID+", warnings="+str(self.Intruders[UserID]['warn']))
            else:
                self.output("Cannot find 'bancmd' variable in "+Extension+" extension")

            self.Intruders[UserID]['banned'] = True

        if saved == True:
            self.ExtensionInfo[Extension]['banafter'] = "immediately"


    def checkByFilters(self, Extension, scan):
        for Item in scan: # lines
            for Filter in self.Filters[Extension]: # filters to use

                # regexp method   
                try:   
                    Success = False
                    if 'regexp' in self.Filters[Extension][Filter]:
                        #print "Matching filter: \""+self.Filters[Extension][Filter]['regexp']+"\" == \""+Item['filter']+"\""
                        # Ignore case?
                        if self.dictGetKey(self.Filters[Extension][Filter], 'casesensitive') == "False":
                            Matches = re.findall(self.Filters[Extension][Filter]['regexp'], Item['filter'], re.IGNORECASE)
                        else:
                            Matches = re.findall(self.Filters[Extension][Filter]['regexp'], Item['filter'])

                        # If found something
                        if len(Matches) > 0:
                            #print Matches
                            # If need to compare two values example from this expression: ([0-9]+)=([0-9]+), $1=$2 will match
                            if self.dictGetKey(self.Filters[Extension][Filter], 'matches'):
                                exp = self.dictGetKey(self.Filters[Extension][Filter], 'matches').split(",")
                                if not len(exp) == 2:
                                    self.output("Invalid count of matches in filter: "+Filter)
                                    continue
                                if len(Matches[0]) >= int(exp[0]) and len(Matches[0]) >= int(exp[1]):
                                    if Matches[0][int(exp[0])] == Matches[0][int(exp[1])]:
                                        Success = True
                            else:
                                Success = True

                        if Success == True:
                            self.takeAction(Extension, self.dictGetKey(self.Filters[Extension][Filter], 'points'), Item['uid'], Filter)

                except Exception as e:
                    self.output("re: "+str(e)+", regexp="+self.Filters[Extension][Filter]['regexp']+", extension="+Extension)

        

                


    def runExtension(self, Extension, data):
        scan = self.Extensions[Extension].parseAll(data)
        self.checkByFilters(Extension, scan)



    def checkLog(self, Extension):
        """ Check if file was modified, load modified lines """
        time.sleep(10)
        Info = self.ExtensionInfo[Extension]
        Array = False
        ModTime = False

        if Info['last_modified'] == 0:
            Array = self.db.getPosition(Info['file'], Extension)
            if not Array == False and not Array == None:
                if self.Options['debug'] == True:
                    self.output("Resuming \""+Info['file']+"\", got position from database")

                self.ExtensionInfo[Extension]['lastline'] = Array['lastline']
                self.ExtensionInfo[Extension]['position'] = Array['position']
                Info['last_modified'] = 1 # required to avoid first time parsing
            else:
                if self.Options['debug'] == True:
                    self.output("No database record for \""+Info['file']+"\"")

            # first time check for modification date of file placed on FTP server
            if not self.dictGetKey(Info, 'ftphost') == False:
                Info['ftpfile'] = Info['file']
                Info['file'] = "/tmp/"+base64.b64encode(Info['ftpfile'])+"_logdetect.tmp"
                self.connectFTPServer(Extension)
                ModTime = int(self.checkoutFTP(Extension))

        else: # check modification date of file placed on FTP server
            if not self.dictGetKey(Info, 'ftphost') == False:
                ModTime = int(self.checkoutFTP(Extension))

        # if not using FTP or other remote method
        if ModTime == False:
            ModTime = os.path.getmtime(Info['file'])

        Info['last_modified'] = int(Info['last_modified'])

        if not Info['last_modified'] == ModTime:

            # downloading fresh, modified file from FTP
            if not self.dictGetKey(Info, 'ftpfile') == False:
                self.downloadFileFTP(Extension)

            # if there is nothing to do just skip it
            if os.path.getsize(Info['file']) == 0:
                return

            # create new handler
            handler = open(Info['file'], 'rb')

            # create position details at first time
            if not 'lastline' in self.ExtensionInfo[Extension]:
                self.ExtensionInfo[Extension]['lastlineid'] = 0
                self.ExtensionInfo[Extension]['lastline'] = ""

            ##### first time parsing the file
            if Info['last_modified'] == 0:
                # ==== SEEK FROM DATABASE MUST BE HERE ==== #

                # load all content from file, from begining to the end
                if Info['start'] == "load_all":
                    contents = handler.readlines()
                    #print "LAST LINE SET: "+contents[(len(contents)-1)]
                    self.ExtensionInfo[Extension]['lastlineid'] = (len(contents)-1)
                    self.ExtensionInfo[Extension]['lastline'] = contents[(len(contents)-1)]
            else:
                ##### continuing already parsed file
                if 'position' in Info:
                    FoundLastLine = False

                    Position = int(Info['position'])

                    # get access to last line from last scan
                    if Position < self.Options['settings']['prebuffer']:
                        Position = 0
                    else:
                        Position -= int(self.Options['settings']['prebuffer'])

                    handler.seek(Position) # go to last position
                    contents_tmp = handler.readlines(int(Info['buffer']))
                    contents = list()

                    for Index, Item in enumerate(contents_tmp):
                        if Item == self.ExtensionInfo[Extension]['lastline']:
                            FoundLastLine = True
                            continue

                        if FoundLastLine == True:
                            contents.append(Item)


                    ##### if last line not found, it will try to search from beginning of file
                    if FoundLastLine == False:
                        self.output("checkLog: Can not find position where the parser was the last in '"+Info['file']+"'")
                        # reset to beginning and search for last line again
                        handler.seek(0)
                        contents = handler.readlines()

                        for Index, Item in enumerate(contents_tmp):
                            if Item == self.ExtensionInfo[Extension]['lastline']:
                                FoundLastLine = True
                                continue

                            if FoundLastLine == True:
                                contents.append(Item)

                        # even if the line was not found at the beginning of the file, it means that the file has been erased
                        if FoundLastLine == False:
                            self.output("Detected that '"+Info['file']+"' was erased, starting from scratch")

                    # free memory from unnecessary code
                    del contents_tmp


                    #print "(AGAIN) LAST LINE SET: "+contents[(len(contents)-1)]
                    
                    if len(contents) > 0:
                        try:
                            self.ExtensionInfo[Extension]['lastlineid'] = int(self.ExtensionInfo[Extension]['lastlineid']) + (len(contents)-1)
                            self.ExtensionInfo[Extension]['lastline'] = contents[(len(contents)-1)]
                        except KeyError as e:
                            self.output("Something went wrong, "+str(e))

                else:
                    contents = handler.readlines()

                    if len(contents) > 0:
                        self.ExtensionInfo[Extension]['lastlineid'] = (len(contents)-1)
                        self.ExtensionInfo[Extension]['lastline'] = contents[(len(contents)-1)]

            # extra debugging on developing stage
            #print("On position: "+str(handler.tell()))
            #print "Contents:"
            #print contents
            #print len(contents)

            # save position to memory and to database

            if len(contents) > 0:
                self.ExtensionInfo[Extension]['position'] = handler.tell()
                self.db.setPosition(Info['file'], Extension, self.ExtensionInfo[Extension]['position'], self.ExtensionInfo[Extension]['lastline'], ModTime)
                self.runExtension(Extension, contents)

            # close file freeing memory
            handler.close()
            self.ExtensionInfo[Extension]['last_modified'] = ModTime
            self.ExtensionInfo[Extension]['state'] = 'idle'
        else:
            return

        self.ExtensionInfo[Extension]['state'] = 'idle'
            





    def monitorFiles(self):
        """ Main loop """

        while True:
            try:
                time.sleep(float(self.Options['settings']['loopinterval']))                

                # time-queue system
                for File in self.Extensions:
                    if not self.ExtensionInfo[File]['state'] == 'executing':
                        if self.ExtensionInfo[File]['wait'] <= 0:
                            # Executing
                            self.ExtensionInfo[File]['wait'] = float(self.ExtensionInfo[File]['timer'])
                            self.ExtensionInfo[File]['state'] = 'executing'
                            
                            # threading
                            current = Thread(target=self.checkLog, args=(File,))
                            current.setDaemon(True)
                            current.start()
                        else:
                            # Waiting
                            self.ExtensionInfo[File]['wait'] -= float(self.Options['settings']['loopinterval'])

            except KeyboardInterrupt:
                self.output("Got interrupt signal, exiting...")
                sys.exit(0)


        



    def main(self):
        self.GNUOpt()
        self.parseConfig(self.Options['config'])

        if self.Options['fork'] == True or 'logging' in self.Options['settings']:
            try:
                self.Options['logging'] = True
                self.log=logging.getLogger('logdetect')
                handler = logging.FileHandler(self.Options['settings']['logging'])
                self.log.addHandler(handler)
                self.log.setLevel(logging.INFO)
            except IOError as e:
                self.output("Cannot access to log file, "+str(e))
                sys.exit(os.EX_OSFILE)

        self.output("logdetect is initializing...")
        self.db = logdatabase()
        self.db.parent = self
        self.db.connectDB()
        # whitelists
        self.loadGlobalWhiteList()
        # main loop
        self.monitorFiles()


    ###### FTP SUPPORT #####
    def MDTM2Timestamp(self, MDTM):
        Date = MDTM[3:].strip()
        return time.mktime(datetime.datetime(int(Date[0:4]), int(Date[4:6]), int(Date[6:8]), int(Date[8:10]), int(Date[10:12]), int(Date[12:14]) ).timetuple())

    def connectFTPServer(self, Extension):
        ftptls = self.dictGetKey(self.ExtensionInfo[Extension], 'ftptls')

        # Use TLS Encryption?
        if not ftptls == False:
            self.ExtensionInfo[Extension]['ftpsocket'] = ftplib.FTP_TLS(self.ExtensionInfo[Extension]['ftphost'])
        else:
            self.ExtensionInfo[Extension]['ftpsocket'] = ftplib.FTP(self.ExtensionInfo[Extension]['ftphost'])
        
        # make a reference
        ftp = self.ExtensionInfo[Extension]['ftpsocket']
        
        # anonymouse or authorized login?
        ftplogin = self.dictGetKey(self.ExtensionInfo[Extension], 'ftplogin')

        if ftplogin == False:
            ftp.login()
        else:
            ftp.login(ftplogin, self.dictGetKey(self.ExtensionInfo[Extension], 'ftppasswd'))

        # Enable TLS
        if not ftptls == False:
            ftp.prot_p()

    def downloadFileFTP(self, Extension):
        self.output("Saving ftp://"+self.ExtensionInfo[Extension]['ftphost']+"/"+self.ExtensionInfo[Extension]['ftpfile']+" to "+self.ExtensionInfo[Extension]['file'])
        outfile = open(self.ExtensionInfo[Extension]['file'], 'wb')
        self.ExtensionInfo[Extension]['ftpsocket'].retrbinary("RETR "+self.ExtensionInfo[Extension]['ftpfile'], outfile.write)
        outfile.close()

    def checkoutFTP(self, Extension):
        try:
            return self.MDTM2Timestamp(self.ExtensionInfo[Extension]['ftpsocket'].sendcmd('MDTM '+self.ExtensionInfo[Extension]['ftpfile']))
        except ftplib.error_perm as e:
            self.output("Error while performing date check. "+str(e))

if __name__ == '__main__': 
    log = logdetect()
    log.main()
