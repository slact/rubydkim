# add our dir to the load path
$:.unshift File.dirname(__FILE__)
require 'signer'
require 'verifier'
# we do DNS lookups in dnsruby
require 'rubygems'
require 'dnsruby'

module DKIM
  class Signature
    attr_accessor :version, :algo, :canon_headers, :canon_body, :querymethod, 
    :selector, :domain, :identity, :created, :expires, :bodylength, 
    :headernames, :copiedheaders, :sigdata, :bodyhash, :signature_header, 
    :verify_status, :verify_ext_status, :pubkey
    
    PDKIM_VERIFY_NONE = 0
    PDKIM_VERIFY_INVALID = 1
    PDKIM_VERIFY_FAIL = 2
    PDKIM_VERIFY_PASS = 3

    PDKIM_VERIFY_FAIL_BODY = 1
    PDKIM_VERIFY_FAIL_MESSAGE = 2
    PDKIM_VERIFY_INVALID_PUBKEY_UNAVAILABLE = 3
    PDKIM_VERIFY_INVALID_BUFFER_SIZE = 4
    PDKIM_VERIFY_INVALID_PUBKEY_PARSING = 5
    
    def passed?
      return verify_status == PDKIM_VERIFY_PASS
    end
    
    def status
      if verify_status == PDKIM_VERIFY_PASS
        :pass
      elsif verify_status == PDKIM_VERIFY_NONE
        :none
      else
        case verify_ext_status
        when PDKIM_VERIFY_FAIL_BODY
          :fail_body
        when PDKIM_VERIFY_FAIL_MESSAGE
          :fail_message
        when PDKIM_VERIFY_INVALID_PUBKEY_UNAVAILABLE
          :invalid_pubkey_unavailable 
        when PDKIM_VERIFY_INVALID_BUFFER_SIZE
          :invalid_buffer_size
        when PDKIM_VERIFY_INVALID_PUBKEY_PARSING
          :invalid_pubkey
        else
          :unknown
        end
      end
    end
    
  end
  
  class Resolver
    # finds the text records for a given domain and joins them into a single data field
    def self.lookup_record(domain)
      resolver = Dnsruby::DNS.new
      resources = resolver.getresources(domain, Dnsruby::Types::TXT)
      if resources
        return resources.collect {|r| r.data}.join
      else
        return ""
      end
    end
  end
end
