#!/usr/bin/env python
# coding=utf-8

"""
Module Name: Basic.py
Create by  : Bluecake
"""

class Basic(object):
    """A basic class
    
    Attributes:
        callbacks: A dict, stores map of names and handlers
    """
    def __init__(self):
        self.callbacks = {}

    def add_callback(self, name, handler):
        self.callbacks[name] = handler 
