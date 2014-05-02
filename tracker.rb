##################################################################
## Ruby BitTorrent Tracker                                      ##
##                                                              ##
##                                                              ##
## Copyright 2008 Vars                                          ##
## Released under the Creative Commons Attribution License      ##
##################################################################

# Require RubyGems
require 'rubygems'
# Require the bencode gem from http://github.com/dasch/ruby-bencode-bindings/tree/master
require 'bencode'
# Require the mysql gem
require 'mysql'
# Require the memcache gem
require 'memcache'
# Require the sinatra gem
require 'sinatra'
# Require YAML to parse config files
require 'yaml'

configure do
  # Load the config
  $config = YAML::load( open('config.yml') )
  # Connect to MySQL
  $db = Mysql::new($config[:mysql][:host], $config[:mysql][:user], $config[:mysql][:pass], $config[:mysql][:database])
  
  whitelist = $db.query( "SELECT Peer_ID, Client FROM whitelist" )
  $whitelist = Array.new
  whitelist.each_hash { |client| $whitelist << { :regex => /#{client['Peer_ID']}/, :name => client['Client'] } } # Put a RegEx of each peerid into $whitelist
end

get '/:passkey/announce' do
  begin
    # Set instance variables for all the query parameters and make sure they exist
    required_params = ['passkey', 'info_hash', 'peer_id', 'port', 'uploaded', 'downloaded', 'left']
    optional_params = ['event', 'compact', 'no_peer_id', 'ip', 'numwant']
    (required_params + optional_params).each do |param|
      error "Bad Announce" if (params[param].nil? or params[param].empty?) and required_params.include?(param)
      self.instance_variable_set("@" + param, escape(params[param]))
    end
    @event ||= 'none'
    @ip ||= escape(@ip)
    @numwant ||= 50
    
    # Make sure client is whitelisted
    whitelisted = $whitelist.map { |client| @peer_id =~ client[:regex] }.include? 0
    error "Your client is banned. Go to #{$config[:whitelist_url]}" unless whitelisted
    
    # Instantiate a cache object for this request
    cache = Cache.new(:host => $config[:cache][:host], :namespace => $config[:cache][:namespace], :passkey => @passkey, :info_hash => @info_hash)
    
    # Find our user
    user = cache.user
    error "Account not found" unless user.exists?
    error "Leeching Disabled" unless user.can_leech?
    
    # Find our torrent
    torrent = $db.query( "SELECT t.ID, t.FreeTorrent FROM torrents AS t WHERE t.info_hash = '#{@info_hash}'" ).fetch_hash
    error "Torrent not found" if torrent.nil?
    
    # Find peers
    peers = $db.query( "SELECT p.UserID, p.IP, p.Port, p.PeerID FROM tracker_peers AS p WHERE TorrentID = '#{torrent['ID']}' ORDER BY RAND() LIMIT #{@numwant}" )
    
    # Log Announce
    $db.query( "INSERT INTO tracker_announce_log (UserID, TorrentID, IP, Port, Event, Uploaded, Downloaded, tracker_announce_log.Left, PeerID, RequestURI, Time) VALUES (#{user['ID']}, #{torrent['ID']}, '#{@ip}', #{@port}, '#{@event}', #{@uploaded}, #{@downloaded}, #{@left}, '#{@peer_id}', '#{escape request.env['QUERY_STRING']}', NOW())" ) if $config[:log_announces]
    
    # Generate Peerlist
    if @compact == '1' # Compact Mode
      peer_list = ''
      peers.each_hash do |peer| # Go through each peer
        ip = peer['IP'].split('.').collect { |octet| octet.to_i }.pack('C*')
        port = [peer['Port'].to_i].pack('n*')
        peer_list << ip + port
      end
    else
      peer_list = []
      peers.each_hash do |peer| # Go through each peer
        peer_hash = { 'ip' => peer['IP'], 'port' => peer['Port'] }
        peer_hash.update( { 'peer id' => peer['PeerID'] } ) unless @no_peer_id == 1
        peer_list << peer_hash
      end
    end
    
    @resp = { 'interval' => $config[:announce_int], 'min interval' => $config[:min_announce_int], 'peers' => peer_list }
    # End peerlist generation
    
    # Update database
    # Update values specific to each event
    case @event
    when 'started'
      # Add the user to the torrents peerlist, then update the seeder / leecher count
      $db.query( "INSERT INTO tracker_peers (UserID, TorrentID, IP, Port, Uploaded, Downloaded, tracker_peers.Left, PeerID) VALUES (#{user['ID']}, #{torrent['ID']}, '#{@ip}', '#{@port}', 0, 0, #{@left}, '#{@peer_id}')" )
      $db.query( "UPDATE torrents SET #{@left.to_i > 0 ? 'Leechers = Leechers + 1' : 'Seeders = Seeders + 1'} WHERE ID = #{torrent['ID']}" )
    when 'completed'
      $db.query( "INSERT INTO tracker_snatches (UserID, TorrentID, IP, Port, Uploaded, Downloaded, PeerID) VALUES (#{user['ID']}, #{torrent['ID']}, '#{@ip}', #{@port}, #{@uploaded}, #{@downloaded}, '#{@peer_id}')" )
      $db.query( "UPDATE torrents SET Seeders = Seeders + 1, Leechers = Leechers - 1, Snatched = Snatched + 1 WHERE ID = #{torrent['ID']}" )
    when 'stopped'
      # Update Seeder / Leecher count for torrent, and update snatched list with final upload / download counts, then delete the user from the torrents peerlist
      $db.query( "UPDATE torrents AS t, tracker_snatches AS s SET #{@left.to_i > 0 ? 't.Leechers = t.Leechers - 1' : 't.Seeders = t.Seeders - 1'}, s.Uploaded = #{@uploaded}, s.Downloaded = #{@downloaded} WHERE t.ID = #{torrent['ID']} AND (s.UserID = #{user['ID']} AND s.TorrentID = #{torrent['ID']})" )
      $db.query( "DELETE FROM tracker_peers WHERE PeerID = '#{@peer_id}' AND TorrentID = #{torrent['ID']}" )
    end
    
    # Update uploaded / downloaded / left amounts
    # This is two queries because we need the old p.Uploaded value to find out what they've uploaded since the last announce, and when it's one query, it uses the current uploaded amount, which is useless since @uploaded - @uploaded = 0, and the user's ratio would never update
    #$db.query( "UPDATE users_main AS u, tracker_peers AS p SET u.Uploaded=u.Uploaded+#{@uploaded}-p.Uploaded, u.Downloaded=u.Downloaded+#{@downloaded}-p.Downloaded WHERE (p.PeerID='#{@peer_id}' AND u.ID=#{user['ID']} AND p.TorrentID=#{torrent['ID']})" )
    user.update(@uploaded, @downloaded)
    $db.query( "UPDATE tracker_peers AS p SET p.Uploaded = #{@uploaded}, p.Downloaded = #{@downloaded}, p.Left = #{@left} WHERE p.PeerID = '#{@peer_id}' AND TorrentID = #{torrent['ID']}" )
    # End database update
    
    @resp.bencode
  rescue TrackerError => e
    e.message
  end
end

get '/:passkey/scrape' do
  {}.bencode
end

get '/stats' do
  Cache.stats
end

helpers do
  def error reason
    raise TrackerError, { 'failure reason' => reason }.bencode
  end
  def escape string
    Mysql::escape_string(string.to_s)
  end
end

# Classes
class TrackerError < RuntimeError; end # Used to clearly identify errors
class Cache
  attr_reader :cache, :mysql, :user, :torrent
  
  def initialize(options = {})
    @cache = MemCache::new options[:host], :namespace => options[:namespace]
        
    unless options[:load_subclasses] == false
      @mysql = options[:mysql]
      @user = User.new(cache, mysql, options[:passkey])
      @torrent = Torrent.new(cache, mysql, options[:info_hash])
    end
  end
  
  def stats
    [cache.get("user_cache_hits")]
  end
  
  class User
    attr_reader :cache, :mysql, :passkey, :user
    
    def initialize(cache, mysql, passkey)
      @cache, @mysql, @passkey, @user = cache, mysql, passkey, self.find
    end
    
    def find
      user = cache.get("user_#{passkey}") # Try to pull the user out of the cache
      cache.incr("user_cache_hits", 1) unless user.nil? # We've got a hit!
      user = self.reload! if user.nil?
    end
    
    def reload!
      user = mysql.query( "SELECT um.ID, um.Enabled, um.can_leech, p.Level FROM users_main AS um LEFT JOIN permissions AS p ON um.PermissionID=p.ID WHERE torrent_pass = '#{@passkey}'" ).fetch_hash
      cache.set("user_#{passkey}", user.merge({ 'Cached' => true }), 60*60*1) # Save the result to the cache, and leave a note saying it was cached
      return user
    end
    
    def update(uploaded, downloaded)
      cache.set("user_#{passkey}_stats", { 'Uploaded' => uploaded, 'Downloaded' => downloaded }, 60*60*1)
      update_list = cache.get("user_update_list")
      update_list << { 'Passkey' => passkey, 'Uploaded' => uploaded, 'Downloaded' => downloaded }
      cache.set("user_update_list", update_list)
    end
    
    def previous_announce
      cache.get("user_#{passkey}_stats")
    end

    def exists?
      user['Enabled'] == '1'
    end

    def can_leech?
      user['can_leech'] == '1'
    end
    
    def cached?
      !!user['Cached']
    end
    
    def to_s # Little hach so that calling cache.user will return the users info
      user
    end
  end
  
  class Torrent
    attr_reader :cache, :mysql, :info_hash
    
    def initialize(cache, mysql, info_hash)
      @cache, @mysql, @info_hash = cache, mysql, info_hash
    end
  end
end