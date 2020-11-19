from django.db import models
from django.db import connection


class MalwareBaseInfo(models.Model):
    uuid = models.CharField(max_length=255)
    malware_md5 = models.CharField(max_length=255)
    malware_class = models.CharField(max_length=255)
    malware_type = models.CharField(max_length=255)
    first_time = models.DateTimeField(blank=True, null=True, serialize=True)
    last_time = models.DateTimeField(blank=True, null=True, serialize=True)
    create_time = models.DateTimeField(blank=True, null=True, serialize=True)
    modified_time = models.DateTimeField(blank=True, null=True, serialize=True)
    level = models.CharField(max_length=255)

    def __str__(self):
        return "{" + "uuid: {0}, malware_md5: {1}, malware_class: {2}, malware_type: {3}, first_time: {4}, last_time: {5}, create_time: {6}, modified_time: {7}, level: {8}".format(
            self.uuid, self.malware_md5, self.malware_class, self.malware_type, self.first_time, self.last_time, self.create_time, self.modified_time, self.level) + "}"


class MalwareOpCode(models.Model):
    uuid = models.CharField(max_length=255)
    file_md5 = models.CharField(max_length=255)
    name = models.CharField(max_length=255)
    caller = models.CharField(max_length=255)
    argc = models.CharField(max_length=255)
    argv = models.CharField(max_length=255)
    return_info = models.CharField(max_length=255)
    index_info = models.CharField(max_length=255)
    dynamic = models.CharField(max_length=255)

    def __str__(self):
        return "{" + "uuid: {0}, file_md5: {1}, name: {2}, caller: {3}, argc: {4}, argv: {5}, return_info: {6}, index: {7}, dynamic: {8}".format(
            self.uuid, self.file_md5, self.name, self.caller, self.argc, self.argv, self.return_info, self.index, self.dynamic) + "}"


class UserNetstateInfo(models.Model):
    ECS_ID = models.CharField(primary_key=True, max_length=50)
    AS_ID = models.CharField(max_length=50)
    VPC_ID = models.CharField(max_length=50)
    Region_ID = models.CharField(max_length=50)

    def __str__(self):
        return "{" + "ECS_ID: {0}, AS_ID: {1}, VPC_ID: {2}, Region_ID: {3}".format(
            self.ECS_ID, self.AS_ID, self.VPC_ID, self.Region_ID) + "}"


# ECS_ID
class ECS_ID(models.Model):
    ECS_ID = models.CharField(max_length=255)
    AS_ID = models.CharField(max_length=255)

    def __str__(self):
        return "{" + "ECS_ID: {0}, AS_ID: {1}".format(self.ECS_ID, self.AS_ID) + "}"


# AS_ID
class AS_ID(models.Model):
    AS_ID = models.CharField(max_length=255)
    VPC_ID = models.CharField(max_length=255)

    def __str__(self):
        return "{" + "AS_ID: {1}, VPC_ID: {2}".format(self.AS_ID, self.VPC_ID) + "}"


# VPC_ID
class VPC_ID(models.Model):
    VPC_ID = models.CharField(max_length=255)
    Region_ID = models.CharField(max_length=255)

    def __str__(self):
        return "{" + "VPC_ID: {2}, Region_ID: {3}".format(self.VPC_ID, self.Region_ID) + "}"
