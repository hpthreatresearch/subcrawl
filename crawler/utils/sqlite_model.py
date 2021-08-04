# © Copyright 2021 HP Development Company, L.P.
import os
from peewee import *
from playhouse.hybrid import hybrid_property
import datetime

db = SqliteDatabase('utils/subcrawl.db')


class BaseModel(Model):
    class Meta:
        database = db


class Domain(BaseModel):
    name = CharField(unique=True)
    description = TextField(null=True)


class Url(BaseModel):
    domain = ForeignKeyField(Domain, backref='urls')
    url = CharField()
    status_code = IntegerField()
    title = CharField(null=True)
    sha256 = CharField()
    last_check = DateTimeField(default=datetime.datetime.utcnow)


class Extension(BaseModel):
    key = CharField()
    value = TextField(null=True)
    url = ForeignKeyField(Url, backref='extensions')


class Tag(BaseModel):
    tag = CharField(unique=True)
    description = TextField(null=True)


class DomainTag(BaseModel):
    domain = ForeignKeyField(Domain, backref='domaintag')
    tag = ForeignKeyField(Tag, backref='domaintag')
