#!/usr/bin/env node
'use strict';
const ldap = require('ldapjs')
const AWS = require('aws-sdk')
const peercred = require('peercred')
const crypto = require('crypto')
const hash = crypto.createHash('sha256')

var secret
if ( process.env.SECRET ) {
  secret = process.env.SECRET
} else {
  hash.update(Array.from('0123456789').map(a=>Math.floor(Math.random() * 100)).join(''))
  secret = hash.digest('hex')
}

console.log ( 'using secret:', secret )

AWS.config.update({region: process.env.AWS_REGION})

var iam = new AWS.IAM({apiVersion: '2010-05-08'})

var server = ldap.createServer()

const domain = process.env.DOMAIN.split('.').map( dc => 'dc=' + dc.toLowerCase() ).join(',')

function authorize(req, res, next) {
  if (isNaN(parseInt(process.env.PORT))){
    let credentials=peercred.fromSock(req.connection)
    if ((process.env.REQUIRE_UID && credentials.uid == process.env.REQUIRE_UID) ||
        (process.env.REQUIRE_GID && credentials.gid == process.env.REQUIRE_GID)) {
      return next()
    } else {
      console.log ('UID or GID mismatch',credentials)
      return next(new ldap.InsufficientAccessRightsError())
    }
  }
  if (!req.connection.ldap.bindDN.equals('cn=root')){
    console.log('user not bound or insufficent rights, try as cn=root')
    return next(new ldap.InsufficientAccessRightsError())
  }
  return next()
}

server.bind('cn=root', function(req, res, next) {
  console.log ( req.credentials )
  if (req.dn.toString() !== 'cn=root' || req.credentials !== secret)
    return next(new ldap.InvalidCredentialsError())

  res.end()
  return next()
}) 

function getUsers (req, res, next) {
  if (! process.env.GROUP_NAME) {
    return next()
  }
  if (!req.users) {
    req.users = {}
  }
  let opts = { GroupName: process.env.GROUP_NAME }
  if (req.marker) {
    opts.Marker = req.marker
  }
  iam.getGroup(opts, (err, data ) => {
    if (err) {
      console.log(err)
      return next(new ldap.UnavailableError())
    }
    let uid = 68000 // more than 16bit max
    data.Users
      .sort((a,b) => a.CreateDate > b.CreateDate) //new users last, only a problem when someone gets deleted
      .forEach ( user => {
        let username = user.Path.replace(/\//g,'')
        if ( username.length ) {
          req.users[username] = {
            dn: 'cn=' + username + ',ou=users,' + domain,
            attributes: {
              cn: username,
              name: user.UserName,
              path: user.Path,
              uri: user.Arn,
              shell: '/bin/bash',
              homedirectory: '/home/' + username,
              uid: uid++, 
              gid: process.env.DEFAULT_GID || 500,
              objectclass: 'unixUser'
            }
          }
        }
      })
    if (data.IsTruncated) {
      req.marker = data.Marker
      getUsers (req, res, next)
    } else {
      next()
    }
  })
}

server.search(domain, authorize, getUsers, function(req, res, next) {
  if (!req.users) {
    console.log('no users found')
    return next(new ldap.UnavailableError())
  }
  Object.keys(req.users).forEach(function(k) {
    if (req.filter.matches(req.users[k].attributes))
      res.send(req.users[k])
  })

  res.end()
})
 
server.listen(process.env.PORT || 1389, function() {
  console.log('ldapjs listening at ' + server.url)
})
