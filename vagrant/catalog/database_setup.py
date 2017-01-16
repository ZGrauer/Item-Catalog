import os
import sys
import datetime
from sqlalchemy import Column, ForeignKey, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()


class User(Base):
    '''Defines a User object.

    Attributes:
        id: Integer PK for table
        name: String 80 character user name. Not null
        email: String 250 character email address. Not null
        picture: String 250 character URL for user profile image

    Methods:

    '''
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(80), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))


class Category(Base):
    '''Defines a Category object.

    Attributes:
        id: Integer PK for table
        name: String 80 character name for the category. Not null
        user_id: Integer FK for the User object who created the Category
        user: table relationship with User object

    Methods:
        serialize: returns the object in a serializable format for JSON
    '''
    __tablename__ = 'category'

    id = Column(Integer, primary_key=True)
    name = Column(String(80), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        '''Returns Item objects in a serializable format to send JSON'''

        return {
            'name': self.name,
            'id': self.id,
        }


class Item(Base):
    '''Defines an Item object for a category.

    Attributes:
        id: Integer PK for table
        name: String 80 character name for the item. Not null
        description: String 500 character description of item.
        create_date: DateTime auto-populated with current date and time
        category_id: Integer FK for the Category object
        user_id: Integer FK for the User object who created the Item
        category: table relationship with Category object
        user: table relationship with User object

    Methods:
        serialize: returns the object in a serializable format for JSON
    '''
    __tablename__ = 'item'

    id = Column(Integer, primary_key=True)
    name = Column(String(80), nullable=False)
    description = Column(String(500))
    create_date = Column(DateTime, default=datetime.datetime.utcnow)
    category_id = Column(Integer, ForeignKey('category.id'))
    user_id = Column(Integer, ForeignKey('user.id'))
    category = relationship(Category)
    user = relationship(User)


    @property
    def serialize(self):
        '''Returns Item objects in a serializable format to send JSON'''

        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'create_date': self.create_date,
            'created_by': self.user.name,
        }


engine = create_engine('sqlite:///catalog.db')

Base.metadata.create_all(engine)
