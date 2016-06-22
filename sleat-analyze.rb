#!/usr/bin/env ruby

# Tom Porter (@porterhau5) & Sanjiv Kawa (@skawasec)

require 'csv'
require 'ipaddr'
require 'resolv'
require 'optparse'

options = {}
optstext = ""

parser = OptionParser.new do |opts|
  opts.banner = "Usage: sleat-analyze.rb [options] <logons.csv> <corp networks> <cde networks> 
    logons.csv    - a CSV produced by sleat-collect.ps1 or sleat-parse.py
    corp networks - newline-delimited file of networks in corporate scope with CIDR notation (ex: 10.5.1.0/24)
    cde networks  - newline-delimited file of networks in CDE scope with CIDR notation (ex: 172.16.10.0/24)

    Example usage
    -------------
    Show scope and user for all logon events (default):
      sleat-analyze.rb logons.csv corp-vlans.txt cde-vlans.txt

    Filter out all corporate hosts:
      sleat-analyze.rb -c logons.csv corp-vlans.txt cde-vlans.txt

    Filter out all machine accounts and exclude domain\\user from output:
      sleat-analyze.rb -mu logons.csv corp-vlans.txt cde-vlans.txt

    Show logons performed by privileged users:
      sleat-analyze.rb -p privusers.txt logons.csv corp-vlans.txt cde-vlans.txt

    Show logons performed by privileged users only from the CDE:
      sleat-analyze.rb -cnp privusers.txt logons.csv corp-vlans.txt cde-vlans.txt\n\n"

  options[:priv] = false
  opts.on('-p privUsersFile', 'File containing newline-delimited list of privileged users. Will only show results for privileged users.') do |privusersfile|
    options[:priv] = true
    options[:privusersfile] = privusersfile
  end

  options[:filteruser] = false
  opts.on('-u', 'Filter out domain\username from output') do
    options[:filteruser] = true
  end

  options[:filtermachine] = false
  opts.on('-m', 'Filter out machine accounts (ex: WIN7-BOB$)') do
    options[:filtermachine] = true
  end

  options[:filternotinscope] = false
  opts.on('-n', 'Filter out hosts not in scope') do
    options[:filternotinscope] = true
  end

  options[:filtercorp] = false
  opts.on('-c', 'Filter out hosts in corp') do
    options[:filtercorp] = true
  end

  options[:filtercde] = false
  opts.on('-d', 'Filter out hosts in CDE') do
    options[:filtercde] = true
  end

  opts.on('-h', '--help', 'Displays help') do
    puts opts
    exit
  end

  optstext = opts
end

parser.parse!

# check args
if ARGV.size != 3
  puts optstext
  exit
end
logonfile, corpfile, cdefile = ARGV

# set counters
cdecount = 0
corpcount = 0
outofscopecount = 0

# Arrays for graphviz dot file
cdeScopeArr = []
inCdeArr = []
inCdeArrFormatted = []
corpScopeArr = []
inCorpArr = []
inCorpArrFormatted = []
notInScopeArr = []

# parse logons file
CSV.foreach(logonfile) do |row|
  ip = row[0].to_s.chomp
  domain = row[1].to_s.chomp
  username = row[2].to_s.chomp
  proceed = false

  # check for privileged users
  if options[:priv]
    File.foreach(options[:privusersfile]) do |privuser|
      # check for "\" in line (indicating domain\username syntax)
      # only want to use username portion for comparisons
      if username.casecmp(privuser.to_s.chomp.split("\\", 2).last).zero?
        proceed = true
      end
    end
  else
    proceed = true
  end

  # filter out machine accounts if appropriate
  if options[:filtermachine]
    if username.end_with?("$")
      proceed = false
    end
  end
 
  # verify IP is an IPv4 address, exclude localhost
  if ip =~ Resolv::IPv4::Regex && ip != "127.0.0.1" && proceed

    # corp networks
    corpscope = false
    File.foreach(corpfile) do |network|
      corpScopeArr.push network
      net = IPAddr.new(network.chomp)
      if net===ip
        corpscope = true
      end
    end

    # CDE networks
    cdescope = false
    File.foreach(cdefile) do |network|
      cdeScopeArr.push network
      net = IPAddr.new(network.chomp)
      if net===ip
        cdescope = true
      end
    end

    # filter dom\user if appropriate
    ret = ""
    if ! options[:filteruser]
      ret << " - #{domain}\\#{username}"
    end

    formatter = ip.split(" ").last.rpartition(".")[0]

    # print scopes
    if cdescope && ! options[:filtercde]
      puts "CDE: #{ip}" + ret
      cdecount += 1
      inCdeArr.push formatter
    elsif corpscope && ! options[:filtercorp]
      puts "Corp: #{ip}" + ret
      corpcount += 1
      inCorpArr.push formatter
    elsif ! corpscope && ! cdescope && ! options[:filternotinscope]
      outofscopecount += 1
      puts "Out: #{ip}" + ret
      notInScopeArr.push formatter
    end
  end
end

# print summary
puts "\nCounts:"
puts "CDE:          #{cdecount}"
puts "Corp:         #{corpcount}"
puts "Out of scope: #{outofscopecount}"

# remove duplicates
notInScopeArr = notInScopeArr.uniq
inCdeArr = inCdeArr.uniq
cdeScopeArr = cdeScopeArr.uniq
inCorpArr = inCorpArr.uniq
corpScopeArr = corpScopeArr.uniq

# formatting array
inCdeArr.each {|x| inCdeArrFormatted.push cdeScopeArr.grep(/#{x}\./)}
inCorpArr.each {|x| inCorpArrFormatted.push corpScopeArr.grep(/#{x}\./)}

# generate dot file for inscope (corp and CDE) hosts
output = File.open( "inscope.dot","w" )
output << "graph neato {\n\n"
output << "node [shape = circle, fixedsize = true, fontcolor = white, fontname = Consolas, fontsize = 8, style = filled, fillcolor = \"#404040\", color= white, width = 1, height = 1, nodesep = 0.1] \n\n"
output << "edge [color = \"#AAAAAA\"]\n"
output << "graph [overlap = false]\n"
output << "DC [label=\"DC1\", fillcolor = \"#7E8F7C\"]\n"
inCdeArrFormatted.each_with_index {|x,i| output << "vlanInCde#{i} [label=\"#{x.join(", ").chomp}\", fillcolor=red, fontcolor=white, style=filled]\n"}
inCorpArrFormatted.each_with_index {|x,i| output << "vlanInCorp#{i} [label=\"#{x.join(", ").chomp}\", fillcolor=\"#C1E1A6\", fontcolor=white, style=filled]\n"}
output << "\n"
inCdeArrFormatted.each_with_index {|x,i| output << "DC -- {vlanInCde#{i}}\n"}
inCorpArrFormatted.each_with_index {|x,i| output << "DC -- {vlanInCorp#{i}}\n"}
output << "\n}"
output.close

# generate dot file for out of scope hosts
output = File.open( "outscope.dot","w" )
output << "graph neato {\n\n"
output << "node [shape = circle, fixedsize = true, fontcolor = white, fontname = Consolas, fontsize = 8, style = filled, fillcolor = \"#404040\", color= white, width = 1, height = 1, nodesep = 0.1] \n\n"
output << "edge [color = \"#AAAAAA\"]\n"
output << "graph [overlap = false]\n"
output << "DC [label=\"DC1\", fillcolor = \"#7E8F7C\"]\n"
notInScopeArr.each_with_index {|x,i| output << "vlanOutOfScope#{i} [label=\"#{x}.0\"]\n"}
output << "\n"
notInScopeArr.each_with_index {|x,i| output << "DC -- {vlanOutOfScope#{i}}\n"}
output << "\n}"
output.close

# remind user to generate PNGs from dot files
puts "\nRun: neato -T png -O inscope.dot && neato -T png -O outscope.dot"
