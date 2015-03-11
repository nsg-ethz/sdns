
class AttributeCombiningMetaclass(type):
  """
  Metaclass to allow union of arbitrary sequence attributes of base classes
  instead of overwriting them.
  Define attributes to combine by setting the attribute
  '_combiningmetaclass_args' in your class.
  
  Order is preserved: Elements from base classes are ordered first.
  """
  
  meta_args_name = '_attr_combining_metaclass_args'
  
  def __new__(cls, name, bases, attrs):
    if cls.meta_args_name in attrs:
      meta_args = attrs[cls.meta_args_name]
      combinable_attrs = meta_args
      del attrs[cls.meta_args_name]
      for attr_name in combinable_attrs:
#         a = []
#         if attr_name in attrs:
#           a = attrs[attr_name]
#         attr_type = type(a) # store type for later, hack
        all_attr_values = [list(attrs.get(attr_name, list()))]
        for base in bases:
          all_attr_values.insert(0,list(getattr(base, attr_name, list()))) # prepend
        
        attr_values = []
        for values in all_attr_values:
          for x in values:
            if x not in attr_values:
              attr_values.append(x)
#       attrs[attr_name] = type(attr_values) # hack, might not work
      attrs[attr_name] = list(attr_values)
    return type.__new__(cls, name, bases, attrs)

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
  

class EventMixin (object):
  _eventMixin_events = set()
  
  def print_events(self):
    print self._eventMixin_events
    
class BaseClass(object):
  
  def __init__(self):
    print "init BaseClass"
    
  def basefun(self):
    print "called basefun"
    
class FirstClass(BaseClass,EventMixin):

  _eventMixin_events = [EventOne]
  
  def __init__(self):
    print "init FirstClass"
    
class SecondClass(BaseClass,EventMixin):

  _eventMixin_events = [EventTwo]
  
  def __init__(self):
    print "init SecondClass"
    
class ThirdClass(FirstClass, SecondClass, EventMixin):
  __metaclass__ = AttributeCombiningMetaclass
  _attr_combining_metaclass_args = ['_eventMixin_events']
  _eventMixin_events = [EventThree]
  
  def __init__(self):
    print "init ThirdClass"
    
class FourthClass(FirstClass, EventMixin):
  __metaclass__ = AttributeCombiningMetaclass
  _attr_combining_metaclass_args = ['_eventMixin_events']
  _eventMixin_events = [EventThree]
  
  def __init__(self):
    print "init FourthClass"
    
class XClass(BaseClass, EventMixin):
  __metaclass__ = AttributeCombiningMetaclass
  _attr_combining_metaclass_args = ['_eventMixin_events']
  _eventMixin_events = [EventOne]
  
  def __init__(self):
    print "init XClass"
    
class YClass(XClass, EventMixin):
  _eventMixin_events = [EventTwo]
  
  def __init__(self):
    print "init YClass"
    
    
class YYClass(YClass):
  pass

if __name__ == '__main__':
  a = ThirdClass()
  a.print_events() # expecting EventOne, Two, Three
  b = FourthClass()
  b.print_events() # expecting EventOne, Three
  c = YClass() 
  c.print_events() # expecting EventOne, Two

  e = YYClass()
  e.print_events() # expecting EventOne, Two
  
  pass




