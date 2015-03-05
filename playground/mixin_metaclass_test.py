'''
Created on Jan 29, 2015

@author: jeremie
'''

import abc
from enum.enum import __new__

class Event(object):
  def __init__(self):
    pass
  
class EventOne(Event):
  def __init__(self):
    self.x = 1
    pass
  
class EventTwo(Event):
  def __init__(self):
    self.x = 2
    pass
  
class EventThree(Event):
  def __init__(self):
    self.x = 3
    pass
  
class EventMixinMetaclass(type):
  def __new__(cls, name, bases, attrs):
    _eventMixin_events = set(attrs.get('_eventMixin_events', list()))
    for base in bases:
        _eventMixin_events.update(base.__dict__.get('_eventMixin_events', list()))
    attrs['_eventMixin_events'] = _eventMixin_events
    return type.__new__(cls, name, bases, attrs)
  
class AbstractEventMixinMetaclass(abc.ABCMeta):
  def __new__(cls, name, bases, attrs):
    _eventMixin_events = set(attrs.get('_eventMixin_events', list()))
    for base in bases:
        _eventMixin_events.update(base.__dict__.get('_eventMixin_events', list()))
    attrs['_eventMixin_events'] = _eventMixin_events
    return abc.ABCMeta.__new__(cls, name, bases, attrs)

class EventMixin (object):
# this also works, but will modify all EventMixin objects which is not desirable
#   __metaclass__ = EventMixinMetaclass
  _eventMixin_events = set()
  
  def print_events(self):
    print self._eventMixin_events
    
class BaseClass(object):
  
  def __init__(self):
    print "init BaseClass"
    
  def basefun(self):
    print "called basefun"
    
class FirstClass(BaseClass,EventMixin):

  _eventMixin_events = set([EventOne])
  
  def __init__(self):
    print "init FirstClass"
    
class SecondClass(BaseClass,EventMixin):

  _eventMixin_events = set([EventTwo])
  
  def __init__(self):
    print "init SecondClass"
    
class ThirdClass(FirstClass, SecondClass, EventMixin):
  __metaclass__ = EventMixinMetaclass
  _eventMixin_events = ([EventThree])
  
  def __init__(self):
    print "init ThirdClass"
    
class FourthClass(FirstClass, EventMixin):
  __metaclass__ = EventMixinMetaclass
  _eventMixin_events = ([EventThree])
  
  def __init__(self):
    print "init FourthClass"
    
class XClass(BaseClass, EventMixin):
  __metaclass__ = EventMixinMetaclass
  _eventMixin_events = ([EventOne])
  
  def __init__(self):
    print "init XClass"
    
class YClass(XClass, EventMixin):
  _eventMixin_events = ([EventTwo])
  
  def __init__(self):
    print "init YClass"
    

class TestAbstractClass(object):
  __metaclass__ = abc.ABCMeta
  def __init__(self,value):
    self.value = value
    pass

  @abc.abstractmethod
  def mymethod(self, value):
    raise NotImplementedError()
  

class TestConcreteClass(TestAbstractClass, EventMixin):
  __metaclass__ = AbstractEventMixinMetaclass
  def __init__(self,value):
    self.value = value

  def mymethod(self, value):
    self.value = value
    
class YYClass(YClass):
  pass

if __name__ == '__main__':
  a = ThirdClass()
  a.print_events() # expecting EventOne, Two, Three
  b = FourthClass()
  b.print_events() # expecting EventOne, Three
  c = YClass() 
  c.print_events() # expecting EventOne, Two

  d = TestConcreteClass(3) # crazy stuff here!
  d.mymethod(5)
  
  e = YYClass()
  e.print_events() # expecting EventOne, Two
  
  pass




