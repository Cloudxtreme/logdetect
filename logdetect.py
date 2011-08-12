#!/usr/bin/python
import os, sys, getopt, re, logging, time, inspect

if sys.version_info.major == 3:
    import configparser
else:
    import ConfigParser as configparser

from time import strftime, localtime
from threading import Thread

# if there is no sqlite3 installed in system it will be turned off safely
try:
    import sqlite3
except Exception:
    True

sys.path.append("/etc/logdetect/modules/")

""" Logdetect - Parse logs and take actions in real time.
     Configuralbe via ini files, parsers and filters.
     Works by detecting threats and identifing its level, if user will reach maximum warnings level will be banned on iptables or in another way using custom command.
"""

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

    def connectDB(self):
        # if database was not set, skip it
        if not self.parent.Options['settings'].has_key('database'):
            return

        try:
            self.socket = sqlite3.connect(self.parent.Options['settings']['database'])
            self.socket.isolation_level = None
            self.cursor = self.socket.cursor()
        except sqlite3.OperationalError as e:
            self.parent.output("logdatabase: "+str(e))
            return

    # save file parsing position to database
    def setPosition(self, Extension, Position):
        return

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
    Extensions = dict()
    ExtensionInfo = dict()
    Filters = dict()
    Intruders = dict()

    def output(self, msg):
        """ Output messages to console or to log file """
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

            exec("import "+extension+".main as CurrentModule")
            Object = CurrentModule.LogdetectExtension(self)
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
            if INI[-2:] == "py" or INI == "__init__.py" or INI == "main.py":
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

                    if not self.ExtensionInfo[Adress].has_key('timer'):
                        self.ExtensionInfo[Adress]['timer'] = 5

                    if not self.ExtensionInfo[Adress].has_key('file'):
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

        if not self.Options['settings'].has_key('loopinterval'):
            self.Options['settings']['loopinterval'] = 1.0

        self.output("Loaded "+str(statExtensions)+" extension(s), "+str(statConfigSections)+" config sections and "+str(statVariables)+" configuration variables")

    def dictGetKey(self, array, key):
        if array.has_key(key):
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

        if not self.Intruders.has_key(str(UserID)):
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
                    if self.Filters[Extension][Filter].has_key('regexp'):
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

        Info = self.ExtensionInfo[Extension]

        if not Info['last_modified'] == os.path.getmtime(Info['file']) and not os.path.getsize(Info['file']) == 0:
            # create new handler
            handler = open(Info['file'], 'rb')

            # create position details at first time
            if not self.ExtensionInfo[Extension].has_key('lastline'):
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
                if Info.has_key('position'):
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

                    # free memory from unnecessary code
                    del contents_tmp


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


                    #print "(AGAIN) LAST LINE SET: "+contents[(len(contents)-1)]
                    
                    if len(contents) > 0:
                        self.ExtensionInfo[Extension]['lastlineid'] = int(self.ExtensionInfo[Extension]['lastlineid']) + (len(contents)-1)
                        self.ExtensionInfo[Extension]['lastline'] = contents[(len(contents)-1)]

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
                #self.db.setPosition(Extension, self.ExtensionInfo[Extension]['position'])
                self.runExtension(Extension, contents)

            # close file freeing memory
            handler.close()
            self.ExtensionInfo[Extension]['last_modified'] = os.path.getmtime(Info['file'])
        else:
            return
            





    def monitorFiles(self):
        """ Main loop """

        while True:
            try:
                time.sleep(float(self.Options['settings']['loopinterval']))
                subThreads = list()

                # time-queue system
                for File in self.Extensions:
                    if self.ExtensionInfo[File]['wait'] <= 0:
                        # Executing
                        self.ExtensionInfo[File]['wait'] = float(self.ExtensionInfo[File]['timer'])
                        
                        # threading
                        current = LogThread("self.Plugin.checkLog(self.sObject)", self, File)
                        current.start()
                    else:
                        # Waiting
                        self.ExtensionInfo[File]['wait'] -= float(self.Options['settings']['loopinterval'])

                for sThread in subThreads:
                    sThread.join()

            except KeyboardInterrupt:
                self.output("Got interrupt signal, exiting...")
                sys.exit(0)


        



    def main(self):
        self.GNUOpt()
        self.output("logdetect 0.1")
        self.parseConfig(self.Options['config'])
        self.db = logdatabase()
        self.db.parent = self
        self.db.connectDB()
        # whitelists
        self.loadGlobalWhiteList()
        # main loop
        self.monitorFiles()

log = logdetect()
log.main()