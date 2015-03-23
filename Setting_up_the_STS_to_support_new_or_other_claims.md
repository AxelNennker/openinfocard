The STS now supports new claims more easily.

# Introduction #

Up until today if you wanted to support new or other claims than the one hardcoded in the example STS, you had to edit several java classes and jsp files (Please see list at bottom of this page).
Now the claims are defined in one file: src/org/xmldap/sts/db/DbSupportedClaims.java


# Details #

To define a claim you have to edit src/org/xmldap/sts/db/DbSupportedClaims.java.

First define the displayTag as an array. Each entry is for a different language:
```
    public final static DbDisplayTag[] dateOfBirthDisplayTagsOA = 
     {new DbDisplayTag("en_US","Date of Birth"), 
      new DbDisplayTag("de_DE","Geburtsdatum")};
```

Then define the supported claim:
```
    public final static DbSupportedClaim dateOfBirthO = 
     new DbSupportedClaim(
      "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/dateofbirth", 
      "dateOfBirth",
      "varChar(50)", 
      dateOfBirthDisplayTagsOA);
```
The first parameter of the constructor is the URI of the claim.
The second parameter is the name of column in the database.
The third parameter is the type of the column in the database.

The rest should be obviously. "Read the source, Luke!"

# List of Files Changed #

  * websrc/xmldap\_sts/cardmanager/createcard.jsp
  * src/org/xmldap/sts/servlet/STSServlet.java
  * src/org/xmldap/sts/db/impl/CardStorageEmbeddedDBImpl.java
  * src/org/xmldap/sts/db/ManagedCard.java src/org/xmldap/infocard/ManagedToken.java
  * src/org/xmldap/sts/db/DbSupportedClaim.java
  * src/org/xmldap/sts/db/DbSupportedClaims.java  src/org/xmldap/sts/db/DbDisplayTag.java






