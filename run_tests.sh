#!/usr/bin/env sh

for file in ./tests/*
do
  tarantool $file
done