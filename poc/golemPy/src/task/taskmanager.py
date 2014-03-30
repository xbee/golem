import random
import time

from taskbase import Task

class TaskManager:
    #######################
    def __init__( self ):
        self.tasks = {}
        self.tasksComputed = []
        #self.givenTasks = {}

    #######################
    def addNewTask( self, task ):
        assert task.header.id not in self.tasks
        self.tasks[ task.header.id ] = task

    #######################
    def getNextSubTask( self, taskId, estimatedPerformance ):
        if taskId in self.tasks:
            task = self.tasks[ taskId ]
            if task.needsComputation():
                ed = task.queryExtraData( estimatedPerformance )
                if ed:
                    #self.givenTasks[ taskId, ed ] = time.time()
                    return taskId, task.srcCode, ed
            print "Cannot get next task for estimated performence {}".format( estimatedPerformance )
            return 0, "", {}
        else:
            print "Cannot find task {} in my tasks".format( taskId )
            return 0, "", {}

    #######################
    def getTasksHeaders( self ):
        ret = []
        for t in self.tasks.values():
            if t.needsComputation():
                ret.append( t.header )

        return ret

    #######################
    def computedTaskReceived( self, taskId, extraData, result ):
        if taskId in self.tasks:
            self.tasks[ taskId ].computationFinished( extraData, result )
            return True
        else:
            print "It is not my task id {}".format( taskId )
            return False

    #######################
    def removeOldTasks( self ):
        for t in self.tasks.values():
            th = t.header
            currTime = time.time()
            th.ttl = th.ttl - ( currTime - th.lastChecking )
            th.lastChecking = currTime
            if th.ttl <= 0:
                print "Task {} dies".format( th.id )
                del self.tasks[ th.id ]

    #######################
    def getProgresses( self ):
        tasksProgresses = {}

        for t in self.tasks.values():
            tasksProgresses[ t.header.id ] = t.getProgress()

        return tasksProgresses