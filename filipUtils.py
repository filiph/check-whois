#!/usr/bin/python
# -*- coding: utf-8 -*-

import codecs, os

def removeDiacritics(str):
    """
    Removes diacritics from a Czech unicode string.
    @param str The unicode string to "de-diacriticize"... :)
    @return A plain string with no i18n characters.
    """
    intab = u"ěščřžýáíéůúóťďňĚŠČŘŽÝÁÍÉŮÚŤĎŇ"
    outtab = u"escrzyaieuuotdnESCRZYAIEUUTDN"
    trantab = dict((ord(a), b) for a, b in zip(intab, outtab))
    return str.translate(trantab)
    
def removeSpaces(str):
    """Removes spaces from a string."""
    trantab = {ord(u" ") : None}
    return str.translate(trantab)
    
def removeDots(str):
    """Removes dots from a string."""
    trantab = {ord(u".") : None}
    return str.translate(trantab)

def addSuffix(filepath, suffix):
    """Will insert suffix to a filepath. Like 'file.txt' -> 'file-suffix.txt'."""
    basename, extension = os.path.splitext(filepath)
    return basename + suffix + extension
    

if __name__ == "__main__":
    teststr = u"svatý mikuláš"
    print(removeSpaces(removeDiacritics(teststr)))