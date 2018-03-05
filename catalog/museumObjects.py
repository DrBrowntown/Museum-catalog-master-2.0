from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Zone, Base, Object, User

engine = create_engine('postgresql://catalog:catalog@localhost/catalog')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()


# Create dummy user
User1 = User(username="Calvin Brownlee", email="calvo115@hotmail.com",
             picture='https://avatars1.githubusercontent.com/u/29411307?s=460&v=4')
session.add(User1)
session.commit()

# Objects in C5 19th C. Tiffany Silver in 
zoneC5 = Zone(user_id=1, name="19th C. Tiffany Silver")

session.add(zoneC5)
session.commit()

object1 = Object(user_id=1, extension="4EC5.1", accession="INV.9070.1-.102",
                     name="Sections of the Atlantic telegraph cable", dimensions="1/2 x 3 7/8 in.", 
                     mount="WALL CLUTCH", misc="NONE", zone=zoneC5)

session.add(object1)
session.commit()

object2 = Object(user_id=1, extension="4EC5.2", accession="2015.31.1",
                     name="Certificate, 6 June 1893", dimensions="21 1/4 x 16 1/2 in.", 
                     mount="WALL MOUNT", misc="NONE", zone=zoneC5)

session.add(object2)
session.commit()

object3 = Object(user_id=1, extension="4EC5.3", accession="INV.774a-c",
                     name="Mourning Bracelet with case", dimensions="Bracelet: 7 1/2 x 1 1/8 in. Case: 3 1/2 x 4 in.", 
                     mount="ANTI WALKER", misc="SHELF", zone=zoneC5)

session.add(object3)
session.commit()

zoneC6 = Zone(user_id=1, name="20th C. Tiffany Silver")

session.add(zoneC6)
session.commit()

object1 = Object(user_id=1, extension="4EC5.1", accession="INV.9070.1-.102",
                     name="Sections of the Atlantic telegraph cable", dimensions="1/2 x 3 7/8 in.", 
                     mount="WALL CLUTCH", misc="NONE", zone=zoneC6)

session.add(object1)
session.commit()

object2 = Object(user_id=1, extension="4EC5.2", accession="2015.31.1",
                     name="Certificate, 6 June 1893", dimensions="21 1/4 x 16 1/2 in.", 
                     mount="WALL MOUNT", misc="NONE", zone=zoneC6)

session.add(object2)
session.commit()

object3 = Object(user_id=1, extension="4EC5.3", accession="INV.774a-c",
                     name="Mourning Bracelet with case", dimensions="Bracelet: 7 1/2 x 1 1/8 in. Case: 3 1/2 x 4 in.", 
                     mount="ANTI WALKER", misc="SHELF", zone=zoneC6)

session.add(object3)
session.commit()

zoneC7 = Zone(user_id=1, name="21st C. Tiffany Silver")

session.add(zoneC7)
session.commit()

object1 = Object(user_id=1, extension="4EC5.1", accession="INV.9070.1-.102",
                     name="Sections of the Atlantic telegraph cable", dimensions="1/2 x 3 7/8 in.", 
                     mount="WALL CLUTCH", misc="NONE", zone=zoneC7)

session.add(object1)
session.commit()

object2 = Object(user_id=1, extension="4EC5.2", accession="2015.31.1",
                     name="Certificate, 6 June 1893", dimensions="21 1/4 x 16 1/2 in.", 
                     mount="WALL MOUNT", misc="NONE", zone=zoneC7)

session.add(object2)
session.commit()

object3 = Object(user_id=1, extension="4EC5.3", accession="INV.774a-c",
                     name="Mourning Bracelet with case", dimensions="Bracelet: 7 1/2 x 1 1/8 in. Case: 3 1/2 x 4 in.", 
                     mount="ANTI WALKER", misc="SHELF", zone=zoneC7)

session.add(object3)
session.commit()

object4 = Object(user_id=1, extension="4EC5.4", accession="INV.9070.1-.102",
                     name="Sections of the Atlantic telegraph cable", dimensions="1/2 x 3 7/8 in.", 
                     mount="WALL CLUTCH", misc="NONE", zone=zoneC7)

session.add(object4)
session.commit()

object5 = Object(user_id=1, extension="4EC5.25", accession="2015.31.1",
                     name="Certificate, 6 June 1893", dimensions="21 1/4 x 16 1/2 in.", 
                     mount="WALL MOUNT", misc="NONE", zone=zoneC7)

session.add(object5)
session.commit()

object6 = Object(user_id=1, extension="4EC5.6", accession="INV.774a-c",
                     name="Mourning Bracelet with case", dimensions="Bracelet: 7 1/2 x 1 1/8 in. Case: 3 1/2 x 4 in.", 
                     mount="ANTI WALKER", misc="SHELF", zone=zoneC7)

session.add(object6)
session.commit()
# Menu for Super Stir Fry



print ("added menu items!")