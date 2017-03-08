<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use DB;
use Mail;
use View;
use Hash;
class ApiController extends Controller
{

		# Reset user password with OTP 
		public function resetpassword()
		{
			$request = json_decode(file_get_contents('php://input'), true);
	 
	    	 
	    	 
	        try{

	        	$conditions = array('email_otp'=>$request['email_otp'],'user_id'=>$request['user_id']);
				$user_details = DB::table('ra_forget_password')->where($conditions)->get()->toArray();
				 
				if(empty($user_details))
				{
					$arrayName = array('success'=>0,'message'=>'This OTP is not correct.');
					return response($arrayName);
				}
				if(!empty($user_details))
				{
					 
					if($user_details[0]->otp_status == 1)
					{
						$arrayName = array('success'=>0,'message'=>'This OTP has been expired.');
						return response($arrayName);
					}
					if($user_details[0]->otp_status == 0)
					{
						if(strlen($request['new_password']) < 6)
						{
						 	$arrayName = array('success'=>0,'message'=>'Please enter minimum six characters in password.');
							return response($arrayName);
						}
						if($request['new_password'] != $request['confirm_password'])
						{
							$arrayName = array('success'=>0,'message'=>'Password mismatch error.');
							return response($arrayName);
						}

						$conditions = array('email_otp'=>$request['email_otp'],'user_id'=>$request['user_id']);
						$update_data = array('otp_status'=>1);
						DB::table('ra_forget_password')->where($conditions)->update($update_data); 
					 	
					 	$conditions = array('user_id'=>$request['user_id']);
						$update_data = array('user_password'=>bcrypt($request['new_password']));
						DB::table('ra_users')->where($conditions)->update($update_data); 

						echo json_encode(array('success'=>1,'message'=>'Password Changes successfully.'));
						exit;
					}
					
 
				    
				} 
	          	
	        }
	        catch(\Exception $e){
	        	//echo dd($e); exit;
	        	
	        	$arrayName = array('success' => 0,'message'=>'something went wrong.');
				return response($arrayName);
	        	//return response('something went wrong',500);
	        }
		}

		# Forget password API 
		public function forgetpassword()
		{
			$request = json_decode(file_get_contents('php://input'), true);
	 
	    	 
	    	 
	        try{

	        	$conditions = array('user_email'=>$request['user_email']);
				$user_details = DB::table('ra_users')->where($conditions)->get()->toArray();
				 
				if(empty($user_details))
				{
						 
						$arrayName = array('success'=>0,'message'=>'This email is not exist.');
				return response($arrayName);
				}
				if(!empty($user_details))
				{
					$conditions = array('user_id'=>$user_details[0]->user_id);
					$update_data = array('otp_status'=>1,'updated_at'=>strtotime("now"));
					DB::table('ra_forget_password')->where($conditions)->update($update_data); 

					$email_otp = $this->intCodeRandom(6);
					$insert_array = array('user_id'=>$user_details[0]->user_id,
					        'user_email' => $user_details[0]->user_email,
					        'email_otp' => $email_otp,
					        'otp_status' => 0,
					        'created_at' => strtotime("now"),
					        'updated_at'=>strtotime("now"));

 					$stable_id = DB::table('ra_forget_password')->insertGetId($insert_array);
					 
					$data = array('otp_code'=>$email_otp);
					$sent_to_email = trim($user_details[0]->user_email);
					$send_email_from = $_ENV['MAIL_USERNAME'];
				    Mail::send('emails.forget_password', $data, function ($message) use ($sent_to_email,$send_email_from) {

				         $message->from($send_email_from, 'Reel App');

				         $message->to($sent_to_email)->subject('Reset password OTP');

				    });
				    echo json_encode(array('success'=>1,'user_id'=>$user_details[0]->user_id));
						exit;
				} 
	          	
	        }
	        catch(\Exception $e){
	        	echo dd($e); exit;
	        	
	        	$arrayName = array('success' => 0,'message'=>'something went wrong.');
				return response($arrayName);
	        	//return response('something went wrong',500);
	        }
		}

		# generate random integer code for email OTP.
		private function intCodeRandom($length)
        {
          $intMin = (10 ** $length) / 10; // 100...
          $intMax = (10 ** $length) - 1;  // 999...

          $codeRandom = mt_rand($intMin, $intMax);

          return $codeRandom;
        }

        # API for Login user 
		public function loginuser()
		{
			 $request = json_decode(file_get_contents('php://input'), true);
	 
	    	 
	    	 
	        try{

	        	$conditions = array('user_name'=>$request['user_name']);
				$user_details = DB::table('ra_users')->where($conditions)->get();
				if(empty($user_details))
				{
						echo json_encode(array('success'=>0,'message'=>'This user name is not exist.'));
						exit;
				}
				if(!empty($user_details))
				{
						if(Hash::check($request['user_password'], $user_details[0]->user_password))
						{
							 
							$user_id = $user_details[0]->user_id;


							$login_token = str_random(24);

							$insert_array = array('user_id'=>$user_id,
					        'login_token' => $login_token,
					        'device_token' => $request['device_token'],
					        'time_zone' => $request['time_zone'],
					        'token_status' => '1',
					        'created_date' => strtotime("now"),
					        'expire_date'=>strtotime("now"));

 
							$stable_id = DB::table('ra_login_sessions')->insertGetId($insert_array);
							 
							$arrayName = array('success' => 1,'user_id'=>$user_id,'login_token'=>$login_token,'email_verify'=>$user_details[0]->email_verify,'data'=>$user_details[0]);
							return response($arrayName);
							 
						}
						else
						{
							echo json_encode(array('success'=>0,'message'=>'This details is not correct.'));
							exit;
						}
				} 
	          	
	        }
	        catch(\Exception $e){
	        	echo dd($e); exit;
	        	
	        	$arrayName = array('success' => 0,'message'=>'something went wrong.');
				return response($arrayName);
	        	//return response('something went wrong',500);
	        }
		}

		# Email verification controller.
		public function emailverification($user_id,$custom_token)
		{
			$conditions = array('user_id'=>$user_id,'custom_token'=>$custom_token);
			$user_info = DB::table('ra_users')->where($conditions)->get()->toArray();
			if(empty($user_info))
			{
				echo "Email verification link is invalid.";
				die;
			}
			if(!empty($user_info))
			{
				$token_status = $user_info[0]->token_status;
				if($token_status == 1)
				{
					$conditions = array('user_id'=>$user_id,'custom_token'=>$custom_token);
					$update_data = array('email_verify'=>1,'updated_at'=>strtotime("now"),'token_status'=>0);
					DB::table('ra_users')->where($conditions)->update($update_data);
					$sent_to_email = trim($user_info[0]->user_email);
					$send_email_from = $_ENV['MAIL_USERNAME'];
					$sdata = array();
				    Mail::send('emails.verfication_success', $sdata, function ($message) use ($sent_to_email,$send_email_from) {

				    $message->from($send_email_from, 'Reel App');

				    $message->to($sent_to_email)->subject('Email Verification successfully.');

				    });

					echo "Email verification successfully.";
					die;
				}
				if($token_status == 0)
				{
					 echo "Email verification link has been expired.";
					 die;
				}
			}
			 
		}


	# API for user registration.
    public function registerUser()
    {
    	$request = json_decode(file_get_contents('php://input'), true);
	    try
	    {

        	if (filter_var($request['user_email'], FILTER_VALIDATE_EMAIL) === false) 
        	{
				 $arrayName = array('success' => 0,'message'=>'This email is not valid.');
				return response($arrayName);
			}  

			$conditions = array('user_email'=>$request['user_email']);
			$count = DB::table('ra_users')->where($conditions)->count();
			if($count == 1)
			{
				$arrayName = array('success' => 0,'message'=>'This email already exists');
				return response($arrayName);
			} 
			
			if(strlen($request['user_name']) < 6)
			{
				$arrayName = array('success' => 0,'message'=>'User name must be six characters.');
				return response($arrayName);
			} 
		 	$request['user_name']  = preg_replace('/[^a-zA-Z0-9_ -]/s','',$request['user_name']);
		 	$conditions = array('user_name'=>$request['user_name']);
			$count = DB::table('ra_users')->where($conditions)->count();
			if($count == 1)
			{
				$arrayName = array('success' => 0,'message'=>'This user name already exists.');
				return response($arrayName);
			}  

			$conditions = array('user_phone_number'=>$request['user_phone_number'],'user_country_code'=>$request['user_country_code']);
			$count = DB::table('ra_users')->where($conditions)->count();
			if($count == 1)
			{
				$arrayName = array('success' => 0,'message'=>'This phone number already exits.');
				return response($arrayName);
			}  

			if(strlen($request['user_password']) < 6)
			{
			 	$arrayName = array('success'=>0,'message'=>'Please enter minimum six characters in password.');
				return response($arrayName);
			}
			$user_id =  rand(200,1000).strtotime("now").rand(10,100);
			$custom_token = rand(10,10000).strtotime("now").rand(20,50000);
			$insert_array = array('user_email' => $request['user_email'],
			        'user_id'=>$user_id,
			        'user_password' => bcrypt($request['user_password']),
			        'user_name' => $request['user_name'],
			        'user_phone_number' => $request['user_phone_number'],
			        'user_country_code' => '+91',
			        'custom_token' => $custom_token,
			        'token_status'=>1,
			        'created_at' => strtotime("now"),
			        'updated_at' => strtotime("now"));

 
			$utable_id = DB::table('ra_users')->insertGetId($insert_array);

			$login_token = str_random(24);
		 
			$insert_array = array('user_id'=>$user_id,
			        'login_token' => $login_token,
			        'device_token' => $request['device_token'],
			        'time_zone' => $request['time_zone'],
			        'token_status' => '1',
			        'created_date' => strtotime("now"),
			        'expire_date'=>strtotime("now"));

 
			$stable_id = DB::table('ra_login_sessions')->insertGetId($insert_array);
        	if($utable_id > 0 && $stable_id > 0)
        	{
        		$verification_link = asset('/')."/index.php/emailverification/".$user_id."/".$custom_token;
				
				$data = array('verification_link'=>$verification_link);
				$sent_to_email = trim($request['user_email']);
				$send_email_from = $_ENV['MAIL_USERNAME'];
			    Mail::send('emails.email_verification', $data, function ($message) use ($sent_to_email,$send_email_from) {

			         $message->from($send_email_from, 'Reel App');

			         $message->to($sent_to_email)->subject('Email Verification');

			    });

			    $sdata = array();
			    Mail::send('emails.register_succefull', $sdata, function ($message) use ($sent_to_email,$send_email_from) {

			    $message->from($send_email_from, 'Reel App');

			    $message->to($sent_to_email)->subject('Thanks for register on Reel app');

			    });
        		$arrayName = array('success' => 1,'user_id'=>$user_id,'login_token'=>$login_token,'email_verify'=>0);
				return response($arrayName);
        	}

        	 
          	
        }
        catch(\Exception $e){
        	echo dd($e); exit;
        	
        	$arrayName = array('success' => 0,'message'=>'something went wrong.');
			return response($arrayName);
        	//return response('something went wrong',500);
        }
    }
}
