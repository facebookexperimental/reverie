cmake_minimum_required(VERSION 3.14)
project(reverie_private_placement C)

find_package(DynamoRIO REQUIRED)
add_library(private_placement_probe SHARED client.c)
configure_DynamoRIO_client(private_placement_probe)
