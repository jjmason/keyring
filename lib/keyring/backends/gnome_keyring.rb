class Keyring::Backend::GnomeKeyring < Keyring::Backend
  register_implementation(self)

  # Supported attributes for our password schema
  SUPPORTED_ATTRIBUTES = %w(server domain user port protocol)

  def supported?
    gnome? && Library.available?
  end

  def get_password service, username
    ptr = FFI::MemoryPointer.new(:pointer)
    rc = call_library :find_password, ptr, server: service, user: username
    return nil if rc.not_found?
    rc.check!
    str_ptr = ptr.read_pointer
    str_ptr.null? ? nil : str_ptr.read_string
  end

  def set_password service, username, password
    call_library! :store_password,
                  nil, # Keyring name (NULL for default)
                  "Generic Password", # Display name, might pick something better at some point
                  password,
                  server: service, user: username
  end

  def delete_password service, username
    call_library! :delete_password, server: service, user: username
  end



  private

  def call_library! *a
    call_library(*a).check!
    nil
  end

  def call_library name, *args
    if args.last.is_a?(Hash)
      args.concat build_varargs(args.pop)
    end
    schema = Library.network_password_schema
    result_code Library.send(:"gnome_keyring_#{name}_sync", schema, *args)
  end

  # Return a ResultCode instance for the given integer
  def result_code code
    ResultCode.new(code)
  end

  # Convert a hash of attributes to a varargs array for FFI.
  def build_varargs attributes
    [].tap do |varargs|
      attributes.keys.map(&:to_s).each do |key|
        raise ArgumentError, "Unsupported attribute \"#{key}\"" unless SUPPORTED_ATTRIBUTES.member?(key)
        varargs << [:string, key, :string, attributes[key].to_s]
      end
      varargs << [:int, 0] # NULL, for varargs
    end.flatten
  end

  # There are a variety of opinions on the right way to check this:
  # http://superuser.com/questions/96151/how-do-i-check-whether-i-am-using-kde-or-gnome
  def gnome?
    ENV['DESKTOP_SESSION'] == 'gnome'
  end

  # Helper for GnomeKeyringResultCode's
  class ResultCode
    VALUES = %w(ok denied no_keyring_daemon already_unlocked no_such_keyring
                bad_arguments io_error cancelled keyring_already_exists not_found)
                .map(&:upcase).map(&:to_sym)

    VALUES.each_with_index do |const, index|
      const_set const, index
      define_method :"#{const.downcase}?" do
        @value == index
      end
    end

    def initialize value
      @value = value
    end

    def check!
      raise "gnome-keyring failed: #{name}" unless ok?
    end

    def name
      self.class::VALUES[@value]
    end

    def to_s
      "<ResultCode: #{name}>"
    end
  end

  # FFI bindings
  module Library

    # Do this in a method instead of the module body, because we might not be on a
    # Gnome platform
    def self.attach_library
      require 'ffi'
      extend ::FFI::Library
      # debian-ish systems install it with the .0 suffix, others
      # with the ordinary name.  If we don't have gnome keyring
      # support at all, this will crash.
      ffi_lib %w(libgnome-keyring.so libgnome-keyring.so.0)

      # We only need the "Simple Password Storage" API, documented
      # at https://developer.gnome.org/gnome-keyring/stable/gnome-keyring-Simple-Password-Storage.html
      # We don't mess around with the asynchronous API, because we don't need it as a backend implementation,
      # and also because working with callbacks in FFI is tricky and error prone.

      # This is a pointer to the network password schema, which we use for this backend
      attach_variable :network_password_schema, :GNOME_KEYRING_NETWORK_PASSWORD, :pointer

      # GnomeKeyringResult  gnome_keyring_store_password_sync   (const GnomeKeyringPasswordSchema *schema, const gchar *keyring, const gchar *display_name, const gchar *password, ...);
      attach_function :gnome_keyring_store_password_sync, [:pointer, :string, :string, :string, :varargs], :int

      # GnomeKeyringResult  gnome_keyring_find_password_sync    (const GnomeKeyringPasswordSchema *schema, gchar **password, ...);
      attach_function :gnome_keyring_find_password_sync, [:pointer, :pointer], :int

      # GnomeKeyringResult  gnome_keyring_delete_password_sync  (const GnomeKeyringPasswordSchema *schema, ...);
      attach_function :gnome_keyring_delete_password_sync, [:pointer], :int
    end

    def self.available?
      @available
    end

    begin
      attach_library
      @available = true
    rescue LoadError
      # empty
    end
  end

end

