# This contains a basic Authlogic web app with
# Register, Login, Logout & a simple My account page
# with a simple cucumber test for login & signup
#
# Make sure you have these gems pre-installed before running these template
# rspec
# rspec-rails
# cucumber
# cucumber-rails
# webrat
# capistrano

run 'cp config/database.yml config/database.yml.example'

# Remove unnecessary Rails files
run 'rm README'
run 'rm public/index.html'
run 'rm public/favicon.ico'
run 'rm public/images/rails.png'

gem 'authlogic', :git => 'git://github.com/binarylogic/authlogic.git'

generate :rspec
generate :cucumber

capify!

file 'Capfile', <<-FILE
  load 'deploy' if respond_to?(:namespace) # cap2 differentiator
  Dir['vendor/plugins/*/recipes/*.rb'].each { |plugin| load(plugin) }
  load 'config/deploy'
FILE

run "touch tmp/.gitignore log/.gitignore"

# Create .gitignore file
file '.gitignore', <<-FILE
.DS_Store
log/*.log
tmp/**/*
config/database.yml
db/*.sqlite3
db/schema.rb
nbproject
FILE


# Setup Basic AuthLogic
# generate user_session model at app/models/user_session.rb
generate(:session, "user_session") 

# generate user_session controller
generate(:controller, "user_sessions")

# map user_sesion resources
route "map.resource :account, :controller => 'users'"
route "map.resource :user_session"
route "map.root :controller => 'user_sessions', :action => 'new'"
route "map.login  '/login',  :controller => 'user_sessions', :action => 'destroy'"

# setup UsesSessionsController
file "app/controllers/user_sessions_controller.rb", <<-FILE
class UserSessionsController < ApplicationController  
  skip_before_filter :require_user # Override application wide filter
  before_filter :require_no_user, :only => [:new, :create]
  before_filter :require_user, :only => :destroy

  def new
    @user_session = UserSession.new
  end

  def create
    @user_session = UserSession.new(params[:user_session])
    if @user_session.save
      flash[:notice] = "Login successful!"
      redirect_back_or_default account_url
    else
      render :action => :new
    end
  end

  def destroy
    current_user_session.destroy
    flash[:notice] = "Logout successful!"
    redirect_back_or_default new_user_session_url
  end
end
FILE

# make user act as authentic
file "app/models/user.rb", <<-FILE
class User < ActiveRecord::Base
  acts_as_authentic
  attr_accessible :login, :email, :password, :password_confirmation
  
  has_many :user_roles, :dependent => :destroy
  has_many :roles, :through => :user_roles
  
  # returns true if the user has the "admin" role, false if not.
  def admin?
    has_role?("admin")
  end

  # returns true if the specified role is associated with the user.
  #  
  #  user.has_role("admin")
  def has_role?(role)
    self.roles.count(:conditions => ["name = ?", role]) > 0
  end
  
  # Adds a role to the user by name
  #
  # user.add_role("mentor")
  def add_role(role)
    return if self.has_role?(role)
    self.roles << Role.find_by_name(role)
  end
end
FILE

file "app/models/role.rb", <<-FILE
class Role < ActiveRecord::Base
  validates_presence_of :name
  
  has_many :user_roles
  has_many :users, :through => :user_roles
end
FILE

file "app/models/user_role.rb", <<-FILE
class UserRole < ActiveRecord::Base
  belongs_to :user
  belongs_to :role
end
FILE

file "app/controllers/users_controller.rb", <<-FILE
class UsersController < ApplicationController
  # Comment the 3 following lines to disable new user registration
  skip_before_filter :require_user # Override application wide filter
  before_filter :require_no_user, :only => [:new, :create]
  before_filter :require_user, :only => [:show, :edit, :update]

  def new
    @user = User.new
  end

  def create
    @user = User.new(params[:user])
    if @user.save
      flash[:notice] = "Account registered!"
      redirect_back_or_default account_url
    else
      render :action => :new
    end
  end

  def show
    @user = @current_user
  end

  def edit
    @user = @current_user
  end

  def update
    @user = @current_user # makes our views "cleaner" and more consistent
    if @user.update_attributes(params[:user])
      flash[:notice] = "Account updated!"
      redirect_to account_url
    else
      render :action => :edit
    end
  end
end
FILE

file "app/controllers/application_controller.rb", <<-FILE
# Filters added to this controller apply to all controllers in the application.
# Likewise, all the methods added will be available for all controllers.

class ApplicationController < ActionController::Base
  before_filter :require_user # Protect the whole app by requiring a logged in user always
  helper :all # include all helpers, all the time
  protect_from_forgery # See ActionController::RequestForgeryProtection for details

  # Scrub sensitive parameters from your log
  # filter_parameter_logging :password
  filter_parameter_logging :password, :password_confirmation
  helper_method :current_user_session, :current_user

  private
    def current_user_session
      return @current_user_session if defined?(@current_user_session)
      @current_user_session = UserSession.find
    end

    def current_user
      return @current_user if defined?(@current_user)
      @current_user = current_user_session && current_user_session.user
    end
    
    def require_user
      unless current_user
        store_location
        flash[:notice] = "You must be logged in to access this page"
        redirect_to new_user_session_url
        return false
      end
    end

    def require_no_user
      if current_user
        store_location
        flash[:notice] = "You must be logged out to access this page"
        redirect_to account_url
        return false
      end
    end

    def store_location
      session[:return_to] = request.request_uri
    end

    def redirect_back_or_default(default)
      redirect_to(session[:return_to] || default)
      session[:return_to] = nil
    end
end
FILE

file "app/views/users/_form.erb", <<-FILE
<%= form.label :login %><br />
<%= form.text_field :login %><br />
<br />
<%= form.label :email %><br />
<%= form.text_field :email %><br />
<br />
<%= form.label :password, form.object.new_record? ? nil : "Change password" %><br />
<%= form.password_field :password %><br />
<br />
<%= form.label :password_confirmation %><br />
<%= form.password_field :password_confirmation %><br />
FILE

file "app/views/users/edit.html.erb", <<-FILE
<h1>Edit My Account</h1>
 
<% form_for @user, :url => account_path do |f| %>
  <%= f.error_messages %>
  <%= render :partial => "form", :object => f %>
  <%= f.submit "Update" %>
<% end %>
 
<br /><%= link_to "My Profile", account_path %>
FILE

file "app/views/users/new.html.erb", <<-FILE
<h1>Register</h1>
 
<% form_for @user, :url => account_path do |f| %>
  <%= f.error_messages %>
  <%= render :partial => "form", :object => f %>
  <%= f.submit "Register" %>
<% end %>
FILE

file "app/views/users/show.html.erb", <<-FILE
<p>
  <b>Login:</b>
  <%=h @user.login %>
</p>
<p>
  <b>Email:</b>
  <%=h @user.email %>
</p>
 
<p>
  <b>Login count:</b>
  <%=h @user.login_count %>
</p>
 
<p>
  <b>Last request at:</b>
  <%=h @user.last_request_at %>
</p>
 
<p>
  <b>Last login at:</b>
  <%=h @user.last_login_at %>
</p>
 
<p>
  <b>Current login at:</b>
  <%=h @user.current_login_at %>
</p>
 
<p>
  <b>Last login ip:</b>
  <%=h @user.last_login_ip %>
</p>
 
<p>
  <b>Current login ip:</b>
  <%=h @user.current_login_ip %>
</p>
 
 
<%= link_to 'Edit', edit_account_path %>
FILE

file "app/views/user_sessions/new.html.erb", <<-FILE
<h1>Login</h1>
 
<% form_for @user_session, :url => user_session_path do |f| %>
  <%= f.error_messages %>
  <%= f.label :login %><br />
  <%= f.text_field :login %><br />
  <br />
  <%= f.label :password %><br />
  <%= f.password_field :password %><br />
  <br />
  <%= f.check_box :remember_me %><%= f.label :remember_me %><br />
  <br />
  <%= f.submit "Submit" %>
<% end %>
FILE

file "app/views/layouts/application.html.erb", <<-FILE
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
       "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head>
  <meta http-equiv="content-type" content="text/html;charset=UTF-8" />
  <title><%= controller.controller_name %>: <%= controller.action_name %></title>
  <%= stylesheet_link_tag 'scaffold' %>
  <%= javascript_include_tag :defaults %>
</head>
<body>

<h1>Authlogic Basic App</h1>
<%= pluralize User.logged_in.count, "user" %> currently logged in<br /> <!-- This based on last_request_at, if they were active < 10 minutes they are logged in -->
<br />
<br />


<% if !current_user %>
  <%= link_to "Register", new_account_path %> |
  <%= link_to "Log In", new_user_session_path %> |
<% else %>
  <%= link_to "My Account", account_path %> |
  <%= link_to "Logout", user_session_path, :method => :delete, :confirm => "Are you sure you want to logout?" %>
<% end %>

<p style="color: green"><%= flash[:notice] %></p>

<%= yield  %>

</body>
</html>
FILE

# Migrations
file "db/migrate/20090621150348_users_and_roles.rb", <<-FILE
class UsersAndRoles < ActiveRecord::Migration
  def self.up
    
    create_table :users do |t|
      t.string    :login,               :null => false                # optional, you can use email instead, or both
      t.string    :email,               :null => false                # optional, you can use login instead, or both
      t.string    :crypted_password,    :default => nil, :null => true
      t.string    :password_salt,       :default => nil, :null => true                # optional, but highly recommended
      t.string    :persistence_token,   :null => false                # required
      t.string    :single_access_token, :null => false                # optional, see Authlogic::Session::Params
      t.string    :perishable_token,    :null => false                # optional, see Authlogic::Session::Perishability
      # t.boolean   :active,              :null => false, :default => false
      # Magic columns, just like ActiveRecord's created_at and updated_at. These are automatically maintained by Authlogic if they are present.
      t.integer   :login_count,         :null => false, :default => 0 # optional, see Authlogic::Session::MagicColumns
      t.integer   :failed_login_count,  :null => false, :default => 0 # optional, see Authlogic::Session::MagicColumns
      t.datetime  :last_request_at                                    # optional, see Authlogic::Session::MagicColumns
      t.datetime  :current_login_at                                   # optional, see Authlogic::Session::MagicColumns
      t.datetime  :last_login_at                                      # optional, see Authlogic::Session::MagicColumns
      t.string    :current_login_ip                                   # optional, see Authlogic::Session::MagicColumns
      t.string    :last_login_ip                                      # optional, see Authlogic::Session::MagicColumns
      t.timestamps
    end
    
    add_index :users, :login
    add_index :users, :persistence_token
    add_index :users, :last_request_at
    

    create_table :roles do |t|
      t.string :name
      t.timestamps
    end
    
    create_table :user_roles do |t|
      t.column :user_id, :integer
      t.column :role_id, :integer
      t.column :created_at, :datetime
    end

    add_index :user_roles, [:user_id, :role_id], :unique => true
    add_index :roles, :name

  end

  def self.down
    remove_index :roles, :name
    remove_index :user_roles, :column => [:user_id, :role_id]
    drop_table "users"
    drop_table "roles"
    drop_table "user_roles"
  end
end
FILE

# Use database (active record) session store
initializer 'session_store.rb', <<-FILE
  ActionController::Base.session = { :session_key => '_#{(1..6).map { |x| (65 + rand(26)).chr }.join}_session', :secret => '#{(1..40).map { |x| (65 + rand(26)).chr }.join}' }
  ActionController::Base.session_store = :active_record_store
FILE

# Cucumber features

# User login
file("features/user_login.feature") do
  <<-EOF
Feature: User login
  In order to access the site
  the user
  wants to login with login and password

  Background:
    Given a user with the login "homer" exists

  Scenario: User login
    Given I go to the homepage
    And I follow "Log In"
    And I fill in "Login" with "homer"
    And I fill in "Password" with "simpson312"
    When I press "Submit"
    Then I should be on the account page
    And I should see "Login successful!"
    And I should see "Login"
    And I should see "Email"
    When I follow "Edit"
    Then I should see "Edit My Account"
  EOF
end

file("features/user_signup.feature") do
  <<-EOF
  Feature: User signup
  In order to login
  User wants to signup and have an account

  Scenario: Register new signup
    Given I am on the homepage
    And I follow "Register"
    And I fill in the following:
      | Login            | user_test |
      | Email            | user@example.com |
      | Password         | mouse321        |
      | Password confirmation | mouse321 |
    When I press "Register"
    Then I should see "Account registered!"

  Scenario: Check for too short email address during signup
    Given I go to the homepage
    And I follow "Register"
    And I fill in "Login" with "homer"
    And I press "Register"
    Then I should see "Email is too short (minimum is 6 characters)"

  Scenario: Checking the password confirmation
    Given I go to the homepage
    And I follow "Register"
    And I fill in "Login" with "homer"
    And I fill in "Email" with "homer@simpsons.com"
    And I fill in "Password" with "homer_rocks"
    And I fill in "Password Confirmation" with "xhomer_rocks"
    When I press "Register"
    Then I should see "Password doesn't match confirmation"

  Scenario: Check for invalid email address during signup
    Given I go to the homepage
    And I follow "Register"
    And I fill in "Login" with "homer"
    And I fill in "Email" with "homer-simpsons.com"
    When I press "Register"
    Then I should see "Email should look like an email address"
  EOF
end

file("features/step_definitions/login_steps.rb") do
  <<-EOF
Given /^a user with the login "([^\"]*)" exists$/ do |login|
  user = User.create do |u|
    u.password = u.password_confirmation = "simpson312"
    u.login = login
    u.email = "homersimpson@test.com"
  end
  user.save
end
  EOF
end

# paths.rb
file("features/support/paths.rb") do
%q{
module NavigationHelpers
  # Maps a name to a path. Used by the
  #
  #   When /^I go to (.+)$/ do |page_name|
  #
  # step definition in webrat_steps.rb
  #
  def path_to(page_name)
    case page_name
    
		when /the home\s?page/
      '/'
    when /the account page/
      '/account'
    
    # Add more mappings here.
    # Here is a more fancy example:
    #
    #   when /^(.*)'s profile page$/i
    #     user_profile_path(User.find_by_login($1))

    else
      raise "Can't find mapping from \"#{page_name}\" to a path.\n" +
        "Now, go and add a mapping in #{__FILE__}"
    end
  end
end

World(NavigationHelpers)
}
end

rake("db:create:all")
rake('db:sessions:create')
rake "db:migrate"

# Set up git repository
git :init
git :add => '.'


# Success!
puts "SUCCESS"
