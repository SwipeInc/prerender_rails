module Rack
  class Prerender
    require 'net/http'
    require 'active_support'

    def initialize(app, options={})
      Rails.logger.debug "#{self.class.name.to_s}::#{__method__}"

      # googlebot, yahoo, and bingbot are not in this list because
      # we support _escaped_fragment_ and want to ensure people aren't
      # penalized for cloaking.
      @crawler_user_agents = [
        # 'googlebot',
        # 'yahoo',
        # 'bingbot',
        'baiduspider',
        'facebookexternalhit',
        'twitterbot',
        'rogerbot',
        'linkedinbot',
        'embedly',
        'bufferbot',
        'quora link preview',
        'showyoubot',
        'outbrain',
        'pinterest/0.',
        'developers.google.com/+/web/snippet',
        'www.google.com/webmasters/tools/richsnippets',
        'slackbot',
        'vkShare',
        'W3C_Validator',
        'redditbot',
        'Applebot',
        'WhatsApp',
        'flipboard',
        'tumblr',
        'bitlybot',
        'SkypeUriPreview',
        'nuzzel',
        'Discordbot',
        'Google Page Speed',
        'Qwantify'
      ]

      @extensions_to_ignore = [
        '.js',
        '.css',
        '.xml',
        '.less',
        '.png',
        '.jpg',
        '.jpeg',
        '.gif',
        '.pdf',
        '.doc',
        '.txt',
        '.ico',
        '.rss',
        '.zip',
        '.mp3',
        '.rar',
        '.exe',
        '.wmv',
        '.doc',
        '.avi',
        '.ppt',
        '.mpg',
        '.mpeg',
        '.tif',
        '.wav',
        '.mov',
        '.psd',
        '.ai',
        '.xls',
        '.mp4',
        '.m4a',
        '.swf',
        '.dat',
        '.dmg',
        '.iso',
        '.flv',
        '.m4v',
        '.torrent'
      ]

      @options = options
      @options[:whitelist] = [@options[:whitelist]] if @options[:whitelist].is_a? String
      @options[:blacklist] = [@options[:blacklist]] if @options[:blacklist].is_a? String
      @extensions_to_ignore = @options[:extensions_to_ignore] if @options[:extensions_to_ignore]
      @crawler_user_agents = @options[:crawler_user_agents] if @options[:crawler_user_agents]
      @app = app
    end


    def call(env)
      Rails.logger.debug "#{self.class.name.to_s}::#{__method__}"

      if should_show_prerendered_page(env)
        Rails.logger.debug "#{self.class.name.to_s}::#{__method__} should show prerendered page"

        cached_response = before_render(env)

        if cached_response
          return cached_response.finish
        end

        prerendered_response = get_prerendered_page_response(env)

        if prerendered_response
          response = build_rack_response_from_prerender(prerendered_response)
          after_render(env, prerendered_response)
          return response.finish
        end
      end

      @app.call(env)
    end

    def get_request_user_agent(env)
      return user_agent = env['HTTP_ROBOT_USER_AGENT'].present? ? env['HTTP_ROBOT_USER_AGENT'] : env['HTTP_USER_AGENT']
    end

    def should_show_prerendered_page(env)
      Rails.logger.debug "#{self.class.name.to_s}::#{__method__}"

      user_agent = get_request_user_agent(env)

      buffer_agent = env['HTTP_X_BUFFERBOT']
      prerender_agent = env['HTTP_X_PRERENDER']
      is_requesting_prerendered_page = false

      return false if !user_agent
      return false if env['REQUEST_METHOD'] != 'GET'

      request = Rack::Request.new(env)

      is_requesting_prerendered_page = true if Rack::Utils.parse_query(request.query_string).has_key?('_escaped_fragment_')

      #if it is a bot...show prerendered page
      is_requesting_prerendered_page = true if @crawler_user_agents.any? { |crawler_user_agent| user_agent.downcase.include?(crawler_user_agent.downcase) }

      #if it is BufferBot...show prerendered page
      is_requesting_prerendered_page = true if buffer_agent

      #if it is Prerender...don't show prerendered page
      is_requesting_prerendered_page = false if prerender_agent

      #if it is a bot and is requesting a resource...dont prerender
      return false if @extensions_to_ignore.any? { |extension| request.fullpath.include? extension }

      #if it is a bot and not requesting a resource and is not whitelisted...dont prerender
      return false if @options[:whitelist].is_a?(Array) && @options[:whitelist].all? { |whitelisted| !Regexp.new(whitelisted).match(request.fullpath) }

      #if it is a bot and not requesting a resource and is blacklisted(url or referer)...dont prerender
      if @options[:blacklist].is_a?(Array) && @options[:blacklist].any? { |blacklisted|
          blacklistedUrl = false
          blacklistedReferer = false
          regex = Regexp.new(blacklisted)

          blacklistedUrl = !!regex.match(request.fullpath)
          blacklistedReferer = !!regex.match(request.referer) if request.referer

          blacklistedUrl || blacklistedReferer
        }
        return false
      end

      return is_requesting_prerendered_page
    end


    def get_prerendered_page_response(env)
      Rails.logger.debug "#{self.class.name.to_s}::#{__method__}"

      begin
        url = URI.parse(build_api_url(env))
        headers = {
          'User-Agent' => get_request_user_agent(env),
          'Accept-Encoding' => 'gzip'
        }
        headers['X-Prerender-Token'] = ENV['PRERENDER_TOKEN'] if ENV['PRERENDER_TOKEN']
        headers['X-Prerender-Token'] = @options[:prerender_token] if @options[:prerender_token]
        req = Net::HTTP::Get.new(url.request_uri, headers)
        req.basic_auth(ENV['PRERENDER_USERNAME'], ENV['PRERENDER_PASSWORD']) if @options[:basic_auth]
        http = Net::HTTP.new(url.host, url.port)
        http.use_ssl = true if url.scheme == 'https'
        response = http.request(req)
        if response['Content-Encoding'] == 'gzip'
          response.body = ActiveSupport::Gzip.decompress(response.body)
          response['Content-Length'] = response.body.length
          response.delete('Content-Encoding')
        end
        response
      rescue
        nil
      end
    end


    def build_api_url(env)
      Rails.logger.debug "#{self.class.name.to_s}::#{__method__}"

      new_env = env
      if env["CF-VISITOR"]
        match = /"scheme":"(http|https)"/.match(env['CF-VISITOR'])
        new_env["HTTPS"] = "on" and new_env["HTTP_X_FORWARDED_SSL"] = "on" and new_env["HTTP_X_FORWARDED_SCHEME"] = "https" and new_env["X_FORWARDED_PROTO"] = "https" and new_env["X_FORWARDED_PORT"] = "443" and new_env["rack.url_scheme"] = "https" and new_env["SERVER_PORT"] = 443 if (match && match[1] == "https")
        new_env["HTTPS"] = false and new_env["rack.url_scheme"] = "http" and new_env["SERVER_PORT"] = 80 if (match && match[1] == "http")
      end

      if env["X-FORWARDED-PROTO"]
        new_env["HTTPS"] = "on" and new_env["HTTP_X_FORWARDED_SSL"] = "on" and new_env["HTTP_X_FORWARDED_SCHEME"] = "https" and new_env["X_FORWARDED_PROTO"] = "https" and new_env["X_FORWARDED_PORT"] = "443" and new_env["rack.url_scheme"] = "https" and new_env["SERVER_PORT"] = 443 if env["X-FORWARDED-PROTO"].split(',')[0] == "https"
        new_env["HTTPS"] = false and new_env["rack.url_scheme"] = "http" and new_env["SERVER_PORT"] = 80 if env["X-FORWARDED-PROTO"].split(',')[0] == "http"
      end

      if @options[:protocol]
        Rails.logger.debug "#{self.class.name.to_s}::#{__method__} #{@options[:protocol]}"

        new_env["HTTPS"] = "on" and new_env["HTTP_X_FORWARDED_SSL"] = "on" and new_env["HTTP_X_FORWARDED_SCHEME"] = "https" and new_env["X_FORWARDED_PROTO"] = "https" and new_env["X_FORWARDED_PORT"] = "443" and new_env["rack.url_scheme"] = "https" and new_env["SERVER_PORT"] = 443 if @options[:protocol] == "https"
        new_env["X_FORWARDED_PROTO"] = "http" and new_env["X_FORWARDED_PORT"] = "80" and new_env["HTTPS"] = false and new_env["rack.url_scheme"] = "http" and new_env["SERVER_PORT"] = 80 if @options[:protocol] == "http"
      end

      url = Rack::Request.new(new_env).url
      prerender_url = get_prerender_service_url()
      forward_slash = prerender_url[-1, 1] == '/' ? '' : '/'

      Rails.logger.debug "#{self.class.name.to_s}::#{__method__} #{prerender_url}#{forward_slash}#{url} "

      "#{prerender_url}#{forward_slash}#{url}"
    end


    def get_prerender_service_url
      @options[:prerender_service_url] || ENV['PRERENDER_SERVICE_URL'] || 'http://service.prerender.io/'
    end


    def build_rack_response_from_prerender(prerendered_response)
      Rails.logger.debug "#{self.class.name.to_s}::#{__method__}"

      response = Rack::Response.new(prerendered_response.body, prerendered_response.code, prerendered_response.header)

      @options[:build_rack_response_from_prerender].call(response, prerendered_response) if @options[:build_rack_response_from_prerender]

      response
    end

    def before_render(env)
      return nil unless @options[:before_render]

      cached_render = @options[:before_render].call(env)

      if cached_render && cached_render.is_a?(String)
        Rack::Response.new(cached_render, 200, { 'Content-Type' => 'text/html; charset=utf-8' })
      elsif cached_render && cached_render.is_a?(Rack::Response)
        cached_render
      else
        nil
      end
    end

    def after_render(env, response)
      return true unless @options[:after_render]
      @options[:after_render].call(env, response)
    end
  end
end
